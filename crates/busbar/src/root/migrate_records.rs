// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Migrate-on-boot steps 4 and 5S/5C on the store side (MIGRATE-ON-BOOT r42 §3 4a, 4b and 5, §6):
//! the seam's `RecordStore` over the opened store, and its calls into `busbar_migrate::records`.
//!
//! [`Store`] delegates the three calls the records step makes (one page of a scan, one atomic
//! commit, the writer authority) to the store FST admission handed the boot, under the owner
//! authority it registered. Each native record the step writes is encoded here with the kernel's
//! own migration encoders and lands where it must be absent; the discovery index rows usage and
//! metering share are written once and matched exactly after that. Each audit record commits with
//! its effects, under [`AUDIT_NS`], and is logged.
//!
//! [`step4`] runs after admission and before step 5: a one-row IMPORT scan; when it holds rows,
//! the attempts are settled (4b) and the R0 rows become native records (4a), their recoverable
//! secrets sealed under the at-rest key the store bootstrap resolved and 1.5.5 self keys verified
//! against the signing key. A stamped boot over an empty IMPORT reads that one row and nothing
//! else.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use busbar_contract::abi::sdk::store::cells::{self, Cell, IMPORT_NS};
use busbar_contract::persistence::{Address, NamespaceId};
use busbar_contract::records::{AuditRecord, MeteringRow, ModelTokens, UsageLedger};
use busbar_contract::secure::SecureVec;
use busbar_kernel::persistence::facade::CoreStore;
use busbar_kernel::persistence::import_target::r0::{Access, Commit, Outcome};
use busbar_kernel::persistence::import_target::records as encode;
use busbar_migrate::records::{
    self, attempts, Audit, Candidate, Committed, Native, RecordStore, Report, StoreFail,
};

/// Where the records step's audit records live: core's own namespace, beside IMPORT, never a
/// plugin's. Key `<WORD>/<16 random bytes, hex>`; value the cells `[word, line]`.
pub(crate) const AUDIT_NS: NamespaceId = NamespaceId(*b"busbar.migrate.a");

/// The file beside config.yaml naming the attempt whose 5d ran in this directory (§A6 "Attempts").
pub(crate) const ATTEMPT_SUFFIX: &str = "busbar-attempt";

/// THE STORE, as the records step reaches it: blocking calls over the admitted store, made from
/// a blocking thread while the boot's runtime drives the store's I/O.
pub(crate) struct Store {
    access: Access,
    runtime: tokio::runtime::Handle,
}

impl Store {
    pub(crate) fn new(core: Arc<CoreStore>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            access: Access::new(core),
            runtime,
        }
    }

    /// `c` as one native commit, `None` when it cannot hold (two records land at one address, or a
    /// shared index row already holds other bytes): the step's VERIFY, nothing written.
    fn native(&self, c: Candidate) -> Result<Option<(Commit, Vec<Audit>)>, StoreFail> {
        let mut commit = Commit::default();
        let mut seen: Vec<Address> = Vec::new();
        let mut claim = |address: &Address| {
            if seen.contains(address) {
                return false;
            }
            seen.push(address.clone());
            true
        };
        for (ns, key, value) in c.exact {
            let address = at(ns, key);
            if !claim(&address) {
                return Ok(None);
            }
            commit.expect.push((address, Some(value)));
        }
        for (ns, key) in c.absent {
            let address = at(ns, key);
            if !claim(&address) {
                return Ok(None);
            }
            commit.expect.push((address, None));
        }
        for (ns, key, value) in c.put {
            commit.put.push((at(ns, key), value));
        }
        for (ns, key) in c.delete {
            commit.delete.push(at(ns, key));
        }
        let mut shared: Vec<(Address, SecureVec)> = Vec::new();
        for native in &c.records {
            let rows = rows_of(native)?;
            for (index, (address, value)) in rows.into_iter().enumerate() {
                if index > 0 && is_shared(native) {
                    match shared.iter().find(|(held, _)| *held == address) {
                        Some((_, held)) if held.as_slice() == value.as_slice() => {}
                        Some(_) => return Ok(None),
                        None => shared.push((address, value)),
                    }
                    continue;
                }
                if !claim(&address) {
                    return Ok(None);
                }
                commit.expect.push((address.clone(), None));
                commit.put.push((address, value));
            }
        }
        for (address, value) in shared {
            if !claim(&address) {
                return Ok(None);
            }
            let stored = self
                .runtime
                .block_on(self.access.read(address.clone()))
                .map_err(StoreFail)?;
            match stored {
                None => {
                    commit.expect.push((address.clone(), None));
                    commit.put.push((address, value));
                }
                Some(stored) if stored.as_slice() == value.as_slice() => {
                    commit.expect.push((address, Some(stored)));
                }
                Some(_) => return Ok(None),
            }
        }
        for audit in &c.audit {
            let address = at(AUDIT_NS, audit_key(audit)?);
            if !claim(&address) {
                return Ok(None);
            }
            let (word, line) = audit_line(audit);
            commit.expect.push((address.clone(), None));
            commit.put.push((
                address,
                SecureVec::from(cells::value(&[Cell::Text(word), Cell::Text(&line)])),
            ));
        }
        Ok(Some((commit, c.audit)))
    }
}

impl RecordStore for Store {
    fn scan(
        &self,
        ns: NamespaceId,
        after: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, SecureVec)>, StoreFail> {
        self.runtime
            .block_on(self.access.scan(ns, after, limit))
            .map_err(StoreFail)
    }

    fn commit(&self, c: Candidate) -> Result<Committed, StoreFail> {
        let Some((commit, audits)) = self.native(c)? else {
            return Ok(Committed::Conflict);
        };
        match self
            .runtime
            .block_on(self.access.commit(commit))
            .map_err(StoreFail)?
        {
            Outcome::Applied => {
                for audit in &audits {
                    let (word, line) = audit_line(audit);
                    tracing::info!(target: "busbar::migrate", "{word}: {line}");
                }
                Ok(Committed::Applied)
            }
            Outcome::Conflict => Ok(Committed::Conflict),
        }
    }

    fn register(&self) -> Result<(), StoreFail> {
        self.access.register().map_err(StoreFail)
    }
}

fn at(ns: NamespaceId, key: Vec<u8>) -> Address {
    Address {
        namespace: ns.0,
        key,
    }
}

/// Usage and metering records carry their discovery index row second; every source row of one
/// window shares it.
fn is_shared(native: &Native) -> bool {
    matches!(native, Native::Usage(_) | Native::Metering(_))
}

fn fail(what: &str, error: impl std::fmt::Debug) -> StoreFail {
    StoreFail(format!(
        "the kernel's encoder refused a converted 1.5.5 {what} ({error:?}); nothing of this page \
         was written"
    ))
}

fn secure_rows(
    rows: Vec<(Address, busbar_contract::Secret<Vec<u8>>)>,
) -> Vec<(Address, SecureVec)> {
    let seal = busbar_kernel::seal::lend();
    rows.into_iter()
        .map(|(address, value)| (address, SecureVec::from(value.expose(&seal).clone())))
        .collect()
}

/// The native rows of one converted record, the kernel's own encoders' bytes.
fn rows_of(native: &Native) -> Result<Vec<(Address, SecureVec)>, StoreFail> {
    let rows = match native {
        Native::Key(key) => encode::identity::migration_key(key).map_err(|e| fail("key", e))?,
        Native::Credential(credential) => {
            // A revoked credential keeps no envelope; 1.5.5's delete removed a tombstoned key's
            // credentials, so none reaches here with its owner tombstoned.
            let envelope = if credential.meta.revoked_at.is_some() {
                &[][..]
            } else {
                credential.secret.as_bytes()
            };
            encode::identity::migration_credential_rows(&credential.meta, envelope, false)
                .map_err(|e| fail("credential", e))?
        }
        Native::Revision(revision) => vec![encode::identity::migration_revision(*revision)
            .map_err(|e| fail("store revision", e))?],
        Native::Deny {
            sub,
            reason,
            created_at,
        } => vec![encode::identity::migration_denied(sub, reason, *created_at)
            .map_err(|e| fail("denied subject", e))?],
        Native::Usage(cell) => {
            let window = u64::try_from(cell.window_start)
                .map_err(|_| fail("usage cell", "a negative window start"))?;
            let ledger = UsageLedger {
                requests: cell.head.requests,
                billable_requests: cell.head.billable_requests,
                models: cell
                    .models
                    .iter()
                    .map(|(model, units)| ModelTokens {
                        scale: busbar_contract::COUNT_SCALE,
                        model: model.clone(),
                        usage_units: tokens(units),
                    })
                    .collect(),
            };
            encode::ledger::migration_usage(&cell.bucket, window, &ledger)
                .map_err(|e| fail("usage cell", e))?
        }
        Native::Metering(row) => {
            let bucket: u64 = row
                .bucket
                .parse()
                .map_err(|_| fail("metering row", "a bucket that is not a whole number"))?;
            let metering = MeteringRow {
                scale: busbar_contract::COUNT_SCALE,
                key_id: row.key_id.clone(),
                model: row.model.clone(),
                provider: row.provider.clone(),
                tokens_input: i128::from(row.units.tokens_input),
                tokens_output: i128::from(row.units.tokens_output),
                tokens_cache_read: i128::from(row.units.tokens_cache_read),
                tokens_cache_write: i128::from(row.units.tokens_cache_write),
                requests: row.units.requests,
                billable_requests: row.units.billable_requests,
                key_group_at_use: row.key_group_at_use.clone(),
                pricing_version: row.pricing_version.clone(),
                priced_from_ms: 0,
                usage_units: Default::default(),
            };
            encode::ledger::migration_metering(bucket, &metering)
                .map_err(|e| fail("metering row", e))?
        }
        Native::Audit(row) => {
            let record = AuditRecord {
                seq: u64::try_from(row.seq).map_err(|_| fail("audit row", "a negative seq"))?,
                ts: u64::try_from(row.ts).map_err(|_| fail("audit row", "a negative time"))?,
                action: row.action.clone(),
                resource: row.resource.clone(),
                outcome: row.outcome.clone(),
                principal: row.principal.clone(),
                prev_hash: row.prev_hash.clone(),
                hash: row.hash.clone(),
            };
            encode::history::migration_audit_rows(encode::AUDIT_OWNER, &record)
                .map_err(|e| fail("audit row", e))?
        }
    };
    Ok(secure_rows(rows))
}

/// The four token classes of one converted entry, already in scale 6; a zero class is not kept.
fn tokens(units: &records::Units) -> std::collections::BTreeMap<String, i128> {
    use busbar_contract::records::{UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT};
    [
        (UNIT_INPUT, units.tokens_input),
        (UNIT_OUTPUT, units.tokens_output),
        (UNIT_CACHE_READ, units.tokens_cache_read),
        (UNIT_CACHE_WRITE, units.tokens_cache_write),
    ]
    .into_iter()
    .filter(|(_, v)| *v != 0)
    .map(|(unit, v)| (unit.to_owned(), i128::from(v)))
    .collect()
}

/// An audit record's word and its one line (no secret: counts, digests and nonces only).
pub(crate) fn audit_line(audit: &Audit) -> (&'static str, String) {
    match audit {
        Audit::RecordsMigrated(report) => ("RECORDS_MIGRATED", report_line(report)),
        Audit::MigrationCompleted(report) => ("MIGRATION_COMPLETED", report_line(report)),
        Audit::RecordsEvolved { from, to, rows } => (
            "RECORDS_EVOLVED",
            format!("record format {from} -> {to}, {rows} rows converted"),
        ),
        Audit::Attempt(attempts::Settled::Completed { digest, nonce }) => (
            "MIGRATION_COMPLETED",
            format!(
                "plan {}, attempt {}",
                hex::encode(digest),
                hex::encode(nonce)
            ),
        ),
        Audit::Attempt(attempts::Settled::Refused {
            digest,
            nonce,
            text,
        }) => (
            "MIGRATION_REFUSED",
            format!(
                "plan {}, attempt {}: {text}",
                hex::encode(digest),
                hex::encode(nonce)
            ),
        ),
        Audit::Attempt(attempts::Settled::Abandoned { digest, nonce }) => (
            "MIGRATION_ABANDONED",
            format!(
                "plan {}, attempt {}",
                hex::encode(digest),
                hex::encode(nonce)
            ),
        ),
    }
}

/// The records step's report, as its audit line.
pub(crate) fn report_line(report: &Report) -> String {
    format!(
        "store format {} -> {}; rows per R0 table {:?}; headless cells {}; ignored {}; audit \
         breaks {}; self_keys_unverified {}; source digest {}",
        report.physical_from,
        report.physical_to,
        &report.rows[1..],
        report.headless_cells,
        report.ignored,
        report.audit_breaks,
        report.self_keys_unverified,
        hex::encode(&report.digest)
    )
}

/// A fresh key under [`AUDIT_NS`] for one audit record.
fn audit_key(audit: &Audit) -> Result<Vec<u8>, StoreFail> {
    let mut nonce = [0u8; 16];
    busbar_contract::crypto::fill(&mut nonce)
        .map_err(|_| StoreFail("the boot drew no entropy for an audit record".to_owned()))?;
    let (word, _) = audit_line(audit);
    Ok(format!("{word}/{}", hex::encode(nonce)).into_bytes())
}

/// `<config>.busbar-attempt`.
pub(crate) fn attempt_file(config: &Path) -> PathBuf {
    let mut name = config.as_os_str().to_owned();
    name.push(".");
    name.push(ATTEMPT_SUFFIX);
    PathBuf::from(name)
}

/// What this directory shows of its own upgrade (§A6 "Attempts"): the stamp, the nonce in
/// `<config>.busbar-attempt`, and config.yaml's SHA-256 now.
pub(crate) fn local(config: &Path) -> attempts::Local {
    let text = std::fs::read(config).unwrap_or_default();
    let stamped = std::str::from_utf8(&text)
        .ok()
        .and_then(|text| busbar_contract::upgrade::config_version(text).ok())
        .is_some_and(|version| version >= busbar_contract::upgrade::CONFIG_FORMAT);
    let nonce = std::fs::read_to_string(attempt_file(config))
        .ok()
        .and_then(|text| {
            let bytes = hex::decode(text.trim()).ok()?;
            <[u8; 16]>::try_from(bytes.as_slice()).ok()
        });
    attempts::Local {
        stamped,
        nonce,
        config_sha256: busbar_contract::crypto::sha256_parts(&[&text]),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The at-rest key and signing key the store bootstrap resolved, for the step's two closures.
pub(crate) struct Keys {
    pub(crate) at_rest: Option<busbar_kernel::governance::at_rest::AtRestKeys>,
    pub(crate) seed: Option<[u8; 32]>,
}

impl Keys {
    /// Moved out of the kernel's bootstrap (once per boot); none when no bootstrap resolved any.
    pub(crate) fn from_bootstrap() -> Self {
        let keys = busbar_kernel::appbuild::take_bootstrap_records_keys();
        Self {
            seed: keys
                .as_ref()
                .and_then(|keys| keys.signer.as_ref())
                .map(busbar_kernel::governance::signing::TokenSigner::secret_bytes),
            at_rest: keys.and_then(|keys| keys.at_rest),
        }
    }
}

/// Steps 4b and 4a over `store`, blocking. `Ok(None)` when IMPORT is empty (one one-row scan).
///
/// # Errors
/// The records step's refusal, its word first (VERIFY, BOUNDS, CONFIG, UNKNOWN, STORE); nothing of
/// a refused page was written and IMPORT still holds every row not converted.
#[cold]
#[inline(never)]
pub(crate) fn run_blocking(
    store: &Store,
    keys: &Keys,
    config: &Path,
    stamped: bool,
) -> Result<Option<Report>, String> {
    // RED: the records step is not run yet (C2 green runs 4b and 4a here).
    if true {
        let _ = (store, keys, config, stamped);
        return Ok(None);
    }
    if store
        .scan(IMPORT_NS, &[], 1)
        .map_err(|fail| format!("STORE: {}", fail.0))?
        .is_empty()
    {
        return Ok(None);
    }
    let settled = attempts::settle(store, &local(config), now()).map_err(|r| r.to_string())?;
    if !settled.is_empty() && local(config).stamped {
        let _ = std::fs::remove_file(attempt_file(config));
    }
    let seal = |meta: &busbar_contract::records::CredentialMeta, plain: &[u8]| {
        keys.at_rest
            .as_ref()
            .ok_or_else(|| "no at-rest key".to_owned())
            .and_then(|at_rest| at_rest.seal(meta, plain))
    };
    let self_id = |sub: &str, epoch: u64| {
        busbar_kernel::governance::self_subject_id(
            keys.seed.as_ref().unwrap_or(&[0; 32]),
            sub,
            epoch,
        )
    };
    let inputs = records::Inputs {
        seal: keys.at_rest.is_some().then_some(&seal as records::Seal<'_>),
        self_id: keys
            .seed
            .is_some()
            .then_some(&self_id as records::SelfId<'_>),
        stamped,
    };
    let report = records::run(store, &inputs).map_err(|r| r.to_string())?;
    Ok(report)
}

/// Step 4 (§3 4a, 4b): after FST admission, before step 5 and before anything serves.
///
/// # Errors
/// As [`run_blocking`]; the boot refuses with the text.
#[cold]
#[inline(never)]
pub(crate) async fn step4(
    core: Arc<CoreStore>,
    config: PathBuf,
    stamped: bool,
) -> Result<(), String> {
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let store = Store::new(core, runtime);
        let keys = Keys::from_bootstrap();
        run_blocking(&store, &keys, &config, stamped)
    })
    .await
    .map_err(|error| format!("the records step did not finish: {error}"))?
    .map(|report| {
        if let Some(report) = report {
            tracing::info!(
                target: "busbar::migrate",
                "the 1.5.5 records were migrated: {}",
                report_line(&report)
            );
        }
    })
}

/// 5S and 5d over the opened store (§A6 "Attempts"): the attempt recorded under IMPORT before
/// the write's first byte, and `<config>.busbar-attempt` naming it just before the rename.
struct Attempt<'a> {
    store: &'a Store,
    config: &'a Path,
    begun: std::cell::RefCell<Option<attempts::Attempt>>,
}

impl busbar_migrate::Attempted for Attempt<'_> {
    fn begin(
        &self,
        digest: [u8; 32],
        written_sha256: [u8; 32],
    ) -> Result<(), busbar_migrate::Refusal> {
        let mut nonce = [0u8; 16];
        busbar_contract::crypto::fill(&mut nonce).map_err(|_| {
            busbar_migrate::Refusal::Config(
                "the boot drew no entropy for the upgrade attempt; nothing was written".to_owned(),
            )
        })?;
        let attempt = attempts::Attempt {
            digest,
            nonce,
            expires_at: now().saturating_add(attempts::EXPIRY_SECS),
            written_sha256,
        };
        attempts::begin(self.store, &attempt)
            .map_err(|refusal| busbar_migrate::Refusal::Config(refusal.to_string()))?;
        *self.begun.borrow_mut() = Some(attempt);
        Ok(())
    }

    fn before_rename(&self) -> Result<(), busbar_migrate::Refusal> {
        let Some(attempt) = self.begun.borrow().clone() else {
            return Ok(());
        };
        let path = attempt_file(self.config);
        let mark = || -> std::io::Result<()> {
            use std::io::Write;
            let mut file = std::fs::File::create(&path)?;
            file.write_all(hex::encode(attempt.nonce).as_bytes())?;
            file.sync_all()
        };
        mark().map_err(|error| {
            busbar_migrate::Refusal::Config(format!(
                "cannot write {} ({error}); config.yaml was not replaced",
                path.display()
            ))
        })
    }
}

/// Step 5's write with the store side (5S, 5d, then 5C or MIGRATION_REFUSED): the attempt is
/// consumed with MIGRATION_COMPLETED once config.yaml is renamed into place, or with
/// MIGRATION_REFUSED and the write's text. A store fault at 5C leaves the attempt and its marker;
/// the next boot's settle completes it.
///
/// # Errors
/// The write's refusal.
#[cold]
#[inline(never)]
pub(crate) fn write_with_attempt(
    store: &Store,
    plan: &busbar_migrate::Plan,
    settled: &[busbar_migrate::Settled],
    check: busbar_migrate::Check<'_>,
    config: &Path,
) -> Result<busbar_migrate::Written, busbar_migrate::Refusal> {
    // RED: no attempt is recorded yet (C2 green records 5S, 5d and 5C).
    if true {
        let _ = (store, config);
        return busbar_migrate::write_settled(plan, settled, check);
    }
    let attempt = Attempt {
        store,
        config,
        begun: std::cell::RefCell::new(None),
    };
    let written = busbar_migrate::write_attempted(plan, settled, check, Some(&attempt));
    if let Some(begun) = attempt.begun.into_inner() {
        let settled = match &written {
            Ok(busbar_migrate::Written::Stamped) => attempts::complete(store, &begun),
            Ok(busbar_migrate::Written::StampedByPeer) => Ok(false),
            Err(refusal) => attempts::refuse(store, &begun, &refusal.to_string()),
        };
        if matches!(settled, Ok(true)) {
            let _ = std::fs::remove_file(attempt_file(config));
        }
    }
    written
}
