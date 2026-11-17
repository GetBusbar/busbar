// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r41 §9 C2 reds for core's records step, over an in-memory [`RecordStore`] with
//! the same predicates the seam's store applies: (a)-(d), (i), (j), (z), (sl1), (sl1b), (sl3),
//! (sl5)(5), (ss1)-(ss4), (h) and the attempts of (n).

use std::cell::{Cell as Counter, RefCell};
use std::collections::BTreeMap;

use busbar_contract::persistence::cells::{self, table, Cell, HEADLESS, IMPORT_NS};
use busbar_contract::persistence::NamespaceId;
use busbar_contract::records::{CredentialMeta, SecretForm};
use busbar_contract::secure::SecureVec;

use super::*;

/// Rows by (namespace, key).
type Rows = BTreeMap<([u8; 16], Vec<u8>), Vec<u8>>;

/// An in-memory store: rows by (namespace, key), native records by address, audit in order.
#[derive(Default)]
struct Mem {
    rows: RefCell<Rows>,
    natives: RefCell<BTreeMap<String, Native>>,
    audit: RefCell<Vec<Audit>>,
    commits: Counter<usize>,
    registers: Counter<usize>,
    scans: Counter<usize>,
    /// The commit (1-based) that fails as a crash: nothing applied, the call errors.
    crash_at: Counter<Option<usize>>,
}

/// Where a native record lands (the seam's address for it).
fn address(n: &Native) -> String {
    match n {
        Native::Key(k) => format!("key/{}", k.id),
        Native::Credential(c) => format!("cred/{}", c.meta.id),
        Native::Revision(_) => "revision".to_owned(),
        Native::Deny { sub, .. } => format!("deny/{sub}"),
        Native::Usage(u) => format!("usage/{}/{}", u.bucket, u.window_start),
        Native::Metering(m) => {
            format!("meter/{}/{}/{}/{}", m.bucket, m.key_id, m.provider, m.model)
        }
        Native::Audit(a) => format!("audit/{}", a.seq),
    }
}

impl Mem {
    fn put(&self, ns: NamespaceId, key: Vec<u8>, value: Vec<u8>) {
        self.rows.borrow_mut().insert((ns.0, key), value);
    }

    fn import(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.rows
            .borrow()
            .iter()
            .filter(|((ns, _), _)| *ns == IMPORT_NS.0)
            .map(|((_, k), v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl RecordStore for Mem {
    fn scan(&self, ns: NamespaceId, after: Option<&[u8]>, limit: u32) -> Result<Page, StoreFail> {
        self.scans.set(self.scans.get() + 1);
        let rows = self.rows.borrow();
        let mut after_rows = rows
            .iter()
            .filter(|((n, k), _)| *n == ns.0 && after.is_none_or(|a| k.as_slice() > a));
        let page: Vec<_> = after_rows
            .by_ref()
            .take(limit as usize)
            .map(|((_, k), v)| (k.clone(), SecureVec::from(v.clone())))
            .collect();
        // The store's own continuation: present while a row follows this page.
        let next = match (page.last(), after_rows.next()) {
            (Some((last, _)), Some(_)) => Some(last.clone()),
            _ => None,
        };
        Ok(Page { rows: page, next })
    }

    fn read(&self, ns: NamespaceId, key: &[u8]) -> Result<Option<SecureVec>, StoreFail> {
        Ok(self
            .rows
            .borrow()
            .get(&(ns.0, key.to_vec()))
            .map(|v| SecureVec::from(v.clone())))
    }

    fn commit(&self, c: Candidate) -> Result<Committed, StoreFail> {
        let n = self.commits.get() + 1;
        self.commits.set(n);
        if self.crash_at.get() == Some(n) {
            return Err(StoreFail("crash".to_owned()));
        }
        let rows = self.rows.borrow();
        let holds = c
            .exact
            .iter()
            .all(|(ns, k, v)| rows.get(&(ns.0, k.clone())).map(Vec::as_slice) == Some(&v[..]))
            && c.absent
                .iter()
                .all(|(ns, k)| !rows.contains_key(&(ns.0, k.clone())))
            && c.records
                .iter()
                .all(|r| !self.natives.borrow().contains_key(&address(r)));
        drop(rows);
        if !holds {
            return Ok(Committed::Conflict);
        }
        let mut rows = self.rows.borrow_mut();
        for (ns, k) in &c.delete {
            rows.remove(&(ns.0, k.clone()));
        }
        for (ns, k, v) in &c.put {
            rows.insert((ns.0, k.clone()), v.to_vec());
        }
        for r in c.records {
            self.natives.borrow_mut().insert(address(&r), r);
        }
        self.audit.borrow_mut().extend(c.audit);
        Ok(Committed::Applied)
    }

    fn register(&self) -> Result<(), StoreFail> {
        self.registers.set(self.registers.get() + 1);
        Ok(())
    }
}

fn key_row(id: &str, name: &str, group: Option<&str>, generation: &str) -> (Vec<u8>, Vec<u8>) {
    let group = group.map_or(Cell::Null, Cell::Text);
    (
        cells::key(table::KEY, &[Cell::Text(id)]),
        cells::value(&[
            Cell::Text(id),
            Cell::Text(name),
            group,
            Cell::Text("[\"default\"]"),
            Cell::Text("{\"team\":\"growth\"}"),
            Cell::Int(1),
            Cell::Text(generation),
            Cell::Int(1_700_000_000),
            Cell::Int(1_700_000_100),
            Cell::Null,
            Cell::Null,
            Cell::Int(7),
        ]),
    )
}

fn credential_row(id: &str, secret: &str) -> (Vec<u8>, Vec<u8>) {
    (
        cells::key(table::CREDENTIAL, &[Cell::Text(id)]),
        cells::value(&[
            Cell::Text(id),
            Cell::Text("vk_1"),
            Cell::Text("sigv4"),
            Cell::Int(0),
            Cell::Text("AKIAEXAMPLE"),
            Cell::Text(secret),
            Cell::Text("recoverable"),
            Cell::Int(1_700_000_000),
            Cell::Int(1_700_000_000),
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Int(9),
        ]),
    )
}

/// A usage cell: `head` = (requests, billable) or `None` for headless; models with 6 counters.
fn usage_row(
    bucket: &str,
    window: i64,
    head: Option<(i64, i64)>,
    models: &[(&str, [i64; 6])],
) -> (Vec<u8>, Vec<u8>) {
    let (requests, billable) = head.unwrap_or((0, 0));
    let mut value = vec![
        Cell::Int(if head.is_some() { 0 } else { HEADLESS }),
        Cell::Text(bucket),
        Cell::Int(window),
        Cell::Int(requests),
        Cell::Int(billable),
    ];
    for (model, counts) in models {
        value.push(Cell::Text(model));
        value.extend(counts.iter().map(|c| Cell::Int(*c)));
    }
    (
        cells::key(table::USAGE, &[Cell::Text(bucket), Cell::Int(window)]),
        cells::value(&value),
    )
}

fn metering_row(model: &str, tokens_input: i64) -> (Vec<u8>, Vec<u8>) {
    let key = [
        Cell::Text("2026-01"),
        Cell::Text("vk_1"),
        Cell::Text("openai"),
        Cell::Text(model),
    ];
    let mut value = key.to_vec();
    value.extend([
        Cell::Text("team"),
        Cell::Text("p1"),
        Cell::Int(3),
        Cell::Int(3),
        Cell::Int(tokens_input),
        Cell::Int(5),
        Cell::Int(0),
        Cell::Int(0),
    ]);
    (cells::key(table::METERING, &key), cells::value(&value))
}

fn audit_row(seq: i64, prev: &str, hash: &str) -> (Vec<u8>, Vec<u8>) {
    (
        cells::key(table::AUDIT, &[Cell::Int(seq)]),
        cells::value(&[
            Cell::Int(seq),
            Cell::Int(1_700_000_000 + seq),
            Cell::Text("key.create"),
            Cell::Text("vk_1"),
            Cell::Text("ok"),
            Cell::Text("admin"),
            Cell::Text(prev),
            Cell::Text(hash),
        ]),
    )
}

/// The rows' fold per table, as a store's verify counts its source.
fn fold_of(key: &[u8], value: &[u8]) -> u64 {
    if cells::tag_of(key) != Some(table::USAGE) {
        return 1;
    }
    let cells = cells::decode(value).unwrap();
    let headless = matches!(cells[0], Cell::Int(f) if f & HEADLESS != 0);
    u64::from(!headless) + ((cells.len() - 5) / 7) as u64
}

/// IMPORT as a store's data step leaves it: `rows` and a SUMMARY that closes over them,
/// `source_extra[tag]` added to the source count (a defect to provoke VERIFY).
fn store_with(rows: &[(Vec<u8>, Vec<u8>)], source_extra: [u64; 8]) -> Mem {
    let mem = Mem::default();
    let mut summary = Summary {
        physical_from: 6,
        physical_to: 7,
        tags: [[0; 4]; 8],
        headless_cells: 0,
        ignored: 2,
        digest: vec![0xab; 32],
    };
    for (key, value) in rows {
        let tag = usize::from(cells::tag_of(key).unwrap());
        summary.tags[tag][0] += fold_of(key, value);
        summary.tags[tag][1] += 1;
        mem.put(IMPORT_NS, key.clone(), value.clone());
    }
    for (tag, extra) in source_extra.iter().enumerate() {
        summary.tags[tag][0] += extra;
    }
    mem.put(IMPORT_NS, SUMMARY_KEY.to_vec(), summary.encode().to_vec());
    mem
}

const NONE: Inputs<'static> = Inputs {
    seal: None,
    self_id: None,
    stamped: false,
};

/// A fixed "seal": the envelope names the credential and the plaintext's length, never its bytes.
fn seal(meta: &CredentialMeta, plain: &[u8]) -> Result<String, String> {
    Ok(format!("v1:aead:kid:{}:{}", meta.id, plain.len()))
}

/// `derive_self_subject` stand-in: the id is a function of the subject and the epoch.
fn self_id(sub: &str, epoch: u64) -> String {
    format!("vk_self_{sub}_{epoch}")
}

/// (a) Every R0 table converts to its native record, and the final commit consumes SUMMARY with
/// RECORDS_MIGRATED on an unstamped boot (MIGRATION_COMPLETED on a stamped one); IMPORT is empty.
#[test]
fn every_r0_table_converts_and_the_final_commit_consumes_summary() {
    let rows = vec![
        key_row("vk_1", "ci", Some("team"), "binding:vk_1:0"),
        (
            cells::key(table::REVISION, &[]),
            cells::value(&[Cell::Int(42)]),
        ),
        (
            cells::key(table::DENY, &[Cell::Text("bob")]),
            cells::value(&[Cell::Text("bob"), Cell::Text("left"), Cell::Int(5)]),
        ),
        usage_row("b1", 60, Some((4, 3)), &[("gpt", [4, 3, 10, 20, 0, 1])]),
        metering_row("gpt", 100),
        audit_row(1, "", "h1"),
        audit_row(2, "h1", "h2"),
    ];
    for stamped in [false, true] {
        let mem = store_with(&rows, [0; 8]);
        let report = run(&mem, &Inputs { stamped, ..NONE }).unwrap().unwrap();
        assert!(mem.import().is_empty(), "IMPORT drained");
        assert_eq!(report.rows, [0, 1, 0, 1, 1, 1, 1, 2]);
        assert_eq!((report.physical_from, report.physical_to), (6, 7));
        assert_eq!(report.ignored, 2);
        assert_eq!(report.audit_breaks, 0);
        let natives = mem.natives.borrow();
        let Some(Native::Key(key)) = natives.get("key/vk_1") else {
            panic!("the key");
        };
        assert_eq!(key.group.as_deref(), Some("team"));
        assert_eq!(key.labels.get("team").map(String::as_str), Some("growth"));
        assert_eq!(key.migrated_from.as_deref(), Some("1.5.5"));
        assert_eq!(key.revision, 7);
        assert_eq!(natives.get("revision"), Some(&Native::Revision(42)));
        let Some(Native::Usage(cell)) = natives.get("usage/b1/60") else {
            panic!("the usage cell");
        };
        assert_eq!(cell.head.requests, 4, "request counts stay whole");
        assert_eq!(cell.models[0].1.tokens_output, 20_000_000);
        let Some(Native::Metering(meter)) = natives.get("meter/2026-01/vk_1/openai/gpt") else {
            panic!("the metering row");
        };
        assert_eq!(meter.units.tokens_input, 100_000_000);
        let audit = mem.audit.borrow();
        assert_eq!(audit.len(), 1);
        match (&audit[0], stamped) {
            (Audit::RecordsMigrated(r), false) | (Audit::MigrationCompleted(r), true) => {
                assert_eq!(r, &report);
            }
            other => panic!("final audit {other:?}"),
        }
    }
}

/// An empty IMPORT is nothing to do: no register, no commit.
#[test]
fn an_empty_import_does_nothing() {
    let mem = Mem::default();
    assert_eq!(run(&mem, &NONE), Ok(None));
    assert_eq!((mem.commits.get(), mem.registers.get()), (0, 0));
}

/// (b) Killed after page k, the next run resumes: no duplicate, no gap, counts still close.
/// (ss4) A self key converted on the first page is not converted twice.
#[test]
fn a_run_killed_after_a_page_resumes_with_no_duplicate_and_no_gap() {
    let mut rows: Vec<_> = (0..5000)
        .map(|i| key_row(&format!("vk_{i:05}"), "k", None, "g"))
        .collect();
    rows.push(key_row(
        &self_id("alice", 1),
        "self-serve key (alice)",
        Some("user:alice"),
        "g",
    ));
    let mem = store_with(&rows, [0; 8]);
    let inputs = Inputs {
        self_id: Some(&self_id),
        ..NONE
    };
    mem.crash_at.set(Some(2));
    assert!(matches!(run(&mem, &inputs), Err(Refusal::Store(_))));
    let first = mem.natives.borrow().len();
    assert_eq!(first, PAGE as usize, "one page applied");
    mem.crash_at.set(None);
    let report = run(&mem, &inputs).unwrap().unwrap();
    assert_eq!(mem.natives.borrow().len(), 5001);
    assert_eq!(report.rows[usize::from(table::KEY)], 5001 - PAGE as u64);
    assert!(mem.import().is_empty());
    let natives = mem.natives.borrow();
    let Some(Native::Key(alice)) = natives.get(&format!("key/{}", self_id("alice", 1))) else {
        panic!("alice's key");
    };
    assert_eq!(alice.idp_subject.as_deref(), Some("alice"));
}

/// (c) A native record already at a row's address: refused, and nothing of the page is written.
#[test]
fn a_pre_existing_native_address_is_refused() {
    let mem = store_with(&[key_row("vk_1", "k", None, "g")], [0; 8]);
    mem.natives
        .borrow_mut()
        .insert("key/vk_1".to_owned(), Native::Revision(0));
    let before = mem.import();
    let refused = run(&mem, &NONE).unwrap_err();
    assert_eq!(refused.word(), "VERIFY", "{refused}");
    assert_eq!(mem.import(), before);
}

/// (d) One multi-model 1.5.5 read key is one native cell; it folds head + models.
#[test]
fn a_multi_model_usage_cell_is_one_native_cell() {
    let rows = [usage_row(
        "b1",
        60,
        Some((7, 7)),
        &[("a", [3, 3, 1, 1, 0, 0]), ("b", [4, 4, 2, 2, 0, 0])],
    )];
    let mem = store_with(&rows, [0; 8]);
    run(&mem, &NONE).unwrap();
    let natives = mem.natives.borrow();
    let Some(Native::Usage(cell)) = natives.get("usage/b1/60") else {
        panic!("one cell");
    };
    assert_eq!(cell.models.len(), 2);
    assert!(!cell.headless);
    assert_eq!(natives.len(), 1);
}

/// (i) SUMMARY one higher than the folds: VERIFY before any core commit, IMPORT byte-identical.
/// (j) The same after a resume at page k.
#[test]
fn counts_that_do_not_close_are_verify_before_any_core_commit() {
    let rows = [usage_row("b1", 60, Some((1, 1)), &[])];
    let mut extra = [0; 8];
    extra[usize::from(table::USAGE)] = 1;
    let mem = store_with(&rows, extra);
    let before = mem.import();
    let refused = run(&mem, &NONE).unwrap_err();
    assert_eq!(refused.word(), "VERIFY", "{refused}");
    assert_eq!((mem.commits.get(), mem.registers.get()), (0, 0));
    assert_eq!(mem.import(), before);

    let rows: Vec<_> = (0..5000)
        .map(|i| key_row(&format!("vk_{i:05}"), "k", None, "g"))
        .collect();
    let mut extra = [0; 8];
    extra[usize::from(table::KEY)] = 1;
    let mem = store_with(&rows, extra);
    // The first pass refuses; a store that resumed at page k (one page consumed) refuses too.
    assert_eq!(run(&mem, &NONE).unwrap_err().word(), "VERIFY");
    let mut fixed = [0; 8];
    fixed[usize::from(table::KEY)] = 0;
    let mem = store_with(&rows, fixed);
    mem.crash_at.set(Some(2));
    let _ = run(&mem, &NONE);
    let held = mem
        .rows
        .borrow()
        .get(&(IMPORT_NS.0, SUMMARY_KEY.to_vec()))
        .cloned()
        .unwrap();
    let mut summary = Summary::decode(&held).unwrap();
    summary.tags[usize::from(table::KEY)][0] += 1;
    mem.put(IMPORT_NS, SUMMARY_KEY.to_vec(), summary.encode().to_vec());
    mem.crash_at.set(None);
    let commits = mem.commits.get();
    let before = mem.import();
    assert_eq!(run(&mem, &NONE).unwrap_err().word(), "VERIFY");
    assert_eq!(
        mem.commits.get(),
        commits,
        "no commit after the resume's pre-check"
    );
    assert_eq!(mem.import(), before);
}

/// (z) Scale 6 never overflows: a counter above `u64::MAX / 10^6` is BOUNDS naming the table,
/// the key, the model and the field, before any commit; the bound itself converts exactly.
#[test]
fn scale6_never_overflows_and_bounds_refuses_before_any_write() {
    assert_eq!(MAX_WHOLE_UNITS, 18_446_744_073_709);
    assert_eq!(scale6(18_446_744_073_709), Some(18_446_744_073_709_000_000));
    assert_eq!(scale6(18_446_744_073_710), None);
    assert_eq!(scale6(-1), None);
    assert_eq!(scale6(i64::MAX), None);

    let over = 18_446_744_073_710;
    let cases = [
        vec![usage_row(
            "b1",
            60,
            Some((1, 1)),
            &[("gpt", [1, 1, over, 0, 0, 0])],
        )],
        vec![usage_row(
            "b1",
            60,
            Some((1, 1)),
            &[("gpt", [1, 1, 0, i64::MAX, 0, 0])],
        )],
        vec![metering_row("gpt", over)],
        vec![usage_row(
            "b1",
            60,
            Some((1, 1)),
            &[
                ("a", [1, 1, 18_446_744_073_709, 0, 0, 0]),
                ("b", [1, 1, 18_446_744_073_709, 0, 0, 0]),
            ],
        )],
    ];
    for rows in cases {
        let mem = store_with(&rows, [0; 8]);
        let before = mem.import();
        let refused = run(&mem, &NONE).unwrap_err();
        assert_eq!(refused.word(), "BOUNDS", "{refused}");
        assert_eq!(mem.commits.get(), 0);
        assert_eq!(mem.import(), before);
        assert!(mem.audit.borrow().is_empty(), "no RECORDS_MIGRATED");
    }
    let mem = store_with(
        &[usage_row(
            "b1",
            60,
            Some((1, 1)),
            &[("gpt", [1, 1, over, 0, 0, 0])],
        )],
        [0; 8],
    );
    let text = run(&mem, &NONE).unwrap_err().to_string();
    for part in [
        "BOUNDS: R0 table 5",
        "bucket b1",
        "window 60",
        "model gpt",
        "`tokens_input`",
    ] {
        assert!(text.contains(part), "{part} in {text}");
    }
    let ok = store_with(
        &[usage_row(
            "b1",
            60,
            Some((1, 1)),
            &[("gpt", [1, 1, 18_446_744_073_709, 0, 0, 0])],
        )],
        [0; 8],
    );
    run(&ok, &NONE).unwrap();
    let natives = ok.natives.borrow();
    let Some(Native::Usage(cell)) = natives.get("usage/b1/60") else {
        panic!("converted");
    };
    assert_eq!(cell.models[0].1.tokens_input, 18_446_744_073_709_000_000);

    // A bad cell in a later page: a resume's pre-check refuses before page k+1 is written.
    let mut rows: Vec<_> = (0..5000)
        .map(|i| usage_row(&format!("b{i:05}"), 60, Some((1, 1)), &[]))
        .collect();
    rows.push(usage_row(
        "zz",
        60,
        Some((1, 1)),
        &[("gpt", [1, 1, over, 0, 0, 0])],
    ));
    let mem = store_with(&rows, [0; 8]);
    assert_eq!(run(&mem, &NONE).unwrap_err().word(), "BOUNDS");
    assert_eq!(mem.commits.get(), 0);
}

/// (sl1) With the at-rest key, each recoverable `v1:plain:` credential is written sealed; the
/// plaintext envelope never reaches a native record.
#[test]
fn recoverable_credentials_are_written_sealed() {
    let rows = [
        credential_row("c1", "v1:plain:secret-one"),
        credential_row("c2", "v1:plain:secret-two"),
    ];
    let mem = store_with(&rows, [0; 8]);
    let inputs = Inputs {
        seal: Some(&seal),
        ..NONE
    };
    run(&mem, &inputs).unwrap();
    for (id, len) in [("c1", 10), ("c2", 10)] {
        let natives = mem.natives.borrow();
        let Some(Native::Credential(c)) = natives.get(&format!("cred/{id}")) else {
            panic!("{id}");
        };
        assert_eq!(c.secret.as_str(), format!("v1:aead:kid:{id}:{len}"));
        assert_eq!(c.meta.secret_form, SecretForm::Recoverable);
        assert_eq!(c.meta.public_id, "AKIAEXAMPLE");
    }
}

/// (sl5)(5), (sl1b) The backstop: plain rows reach the step with no key, so CONFIG with the
/// "already migrated by its plugin" text; IMPORT byte-identical and no native credential.
#[test]
fn plain_rows_without_a_key_refuse_config_before_any_write() {
    let rows = [
        credential_row("c1", "v1:plain:a"),
        credential_row("c2", "v1:plain:b"),
    ];
    let mem = store_with(&rows, [0; 8]);
    let before = mem.import();
    let refused = run(&mem, &NONE).unwrap_err();
    assert_eq!(refused, Refusal::Config(already_migrated_text(2)));
    assert!(refused
        .to_string()
        .contains("already migrated by its plugin"));
    assert_eq!((mem.commits.get(), mem.registers.get()), (0, 0));
    assert_eq!(mem.import(), before);
    assert!(mem.natives.borrow().is_empty());
}

/// (sl3) The drop-in case: no credential row, no key: the store migrates.
#[test]
fn no_recoverable_row_and_no_key_migrates() {
    let mem = store_with(&[key_row("vk_1", "k", None, "g")], [0; 8]);
    assert!(run(&mem, &NONE).unwrap().is_some());
}

/// A recoverable secret that is not a `v1:plain:` envelope is not what 1.5.5 wrote: UNKNOWN.
#[test]
fn a_recoverable_secret_without_the_plain_envelope_is_unknown() {
    let mem = store_with(&[credential_row("c1", "v1:other:x")], [0; 8]);
    assert_eq!(run(&mem, &NONE).unwrap_err().word(), "UNKNOWN");
}

/// (ss1) A 1.5.5 self key survives: its id is its subject's, so it is user-bound to `alice`, no
/// provider yet, and every other field unchanged. (ss2) Moved to another group, or rotated (a
/// random generation, so its epoch is found by the probe): still converted.
#[test]
fn self_keys_are_converted_when_their_id_is_their_subjects() {
    let rows = [
        key_row(
            &self_id("alice", 0),
            "self-serve key (alice)",
            Some("user:alice"),
            "binding:x:0",
        ),
        key_row(
            &self_id("bob", 3),
            "self-serve key (bob)",
            Some("team"),
            &format!("binding:{}:3", self_id("bob", 3)),
        ),
        key_row(
            &self_id("carol", 200),
            "self-serve key (carol)",
            Some("user:carol"),
            "random",
        ),
    ];
    let mem = store_with(&rows, [0; 8]);
    let report = run(
        &mem,
        &Inputs {
            self_id: Some(&self_id),
            ..NONE
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(report.self_keys_unverified, 0);
    for (sub, epoch) in [("alice", 0), ("bob", 3), ("carol", 200)] {
        let natives = mem.natives.borrow();
        let Some(Native::Key(key)) = natives.get(&format!("key/{}", self_id(sub, epoch))) else {
            panic!("{sub}");
        };
        assert_eq!(key.idp_subject.as_deref(), Some(sub));
        assert_eq!(key.binding_mode.as_deref(), Some("user-bound"));
        assert_eq!(key.idp_provider, None);
        assert_eq!(key.revision, 7, "every other field unchanged");
    }
}

/// (ss3) An admin-minted key with a random id in `user:alice` keeps its 1.5.5 shape and is
/// counted; with no signing key every self row is unverified and the step proceeds.
#[test]
fn unverifiable_self_keys_keep_their_shape_and_are_counted() {
    let rows = [
        key_row("vk_random", "ops", Some("user:alice"), "g"),
        key_row("vk_plain", "ops", Some("team"), "g"),
    ];
    for (inputs, unverified) in [
        (
            Inputs {
                self_id: Some(&self_id),
                ..NONE
            },
            1,
        ),
        (NONE, 1),
    ] {
        let mem = store_with(&rows, [0; 8]);
        let report = run(&mem, &inputs).unwrap().unwrap();
        assert_eq!(report.self_keys_unverified, unverified);
        let natives = mem.natives.borrow();
        let Some(Native::Key(key)) = natives.get("key/vk_random") else {
            panic!("kept");
        };
        assert_eq!(key.idp_subject, None);
        assert_eq!(key.binding_mode, None);
    }
}

/// Audit rows keep their hashes; a broken `prev_hash` link is counted, not refused.
#[test]
fn audit_rows_keep_their_hashes_and_breaks_are_counted() {
    let rows = [
        audit_row(1, "", "h1"),
        audit_row(2, "zz", "h2"),
        audit_row(3, "h2", "h3"),
    ];
    let mem = store_with(&rows, [0; 8]);
    let report = run(&mem, &NONE).unwrap().unwrap();
    assert_eq!(report.audit_breaks, 1);
    assert_eq!(
        mem.natives.borrow().get("audit/2"),
        Some(&Native::Audit(AuditRow {
            seq: 2,
            ts: 1_700_000_002,
            action: "key.create".to_owned(),
            resource: "vk_1".to_owned(),
            outcome: "ok".to_owned(),
            principal: "admin".to_owned(),
            prev_hash: "zz".to_owned(),
            hash: "h2".to_owned(),
        }))
    );
}

const MANIFEST_NS: NamespaceId = NamespaceId(*b"busbar.format1\0\0");
const DATA_NS: NamespaceId = NamespaceId(*b"test.records.v1\0");

fn manifest_bytes(format: u32, tail: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 80];
    bytes[8..12].copy_from_slice(&format.to_le_bytes());
    bytes[72..76].copy_from_slice(&tail.to_le_bytes());
    bytes
}

fn manifest_of(mem: &Mem) -> Vec<u8> {
    mem.rows
        .borrow()
        .get(&(MANIFEST_NS.0, b"active".to_vec()))
        .cloned()
        .unwrap()
}

/// The fixture step 1 → 2: prefixes every value of DATA_NS with `2:`.
fn to_two(_: NamespaceId, _: &[u8], value: &[u8]) -> Result<SecureVec, Refusal> {
    let mut out = b"2:".to_vec();
    out.extend_from_slice(value);
    Ok(SecureVec::from(out))
}

const FIXTURE: &[RecordStep] = &[RecordStep {
    from: 1,
    namespaces: &[DATA_NS],
    convert: to_two,
}];

fn evolve_store(rows: usize, format: u32, tail: u32) -> Mem {
    let mem = Mem::default();
    mem.put(
        MANIFEST_NS,
        b"active".to_vec(),
        manifest_bytes(format, tail),
    );
    for i in 0..rows {
        mem.put(DATA_NS, format!("r{i:05}").into_bytes(), b"v".to_vec());
    }
    mem
}

fn evolve_once(mem: &Mem, steps: &[RecordStep], current: u32) -> Result<Option<u64>, Refusal> {
    let bytes = manifest_of(mem);
    let format = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let tail = u32::from_le_bytes(bytes[72..76].try_into().unwrap());
    evolve_with(
        mem,
        steps,
        current,
        &Manifest {
            ns: MANIFEST_NS,
            key: b"active",
            bytes: &bytes,
            format,
            migrating_to: tail,
            encode: &manifest_bytes,
        },
    )
}

/// (h) The record-format chain: a format-1 store with 9,000 rows is admitted at 2, every row
/// converted, manifest (2, 0), one RECORDS_EVOLVED; killed after a page it resumes from the cursor
/// with no row converted twice. (#319 r4 §7.3: the flip is its own zero-payload commit after the
/// last page; see `the_final_publication_is_an_empty_commit_after_the_payload`.)
#[test]
fn the_record_format_chain_converts_in_pages_and_flips_atomically() {
    let mem = opened_store(9000);
    assert_eq!(evolve_once(&mem, FIXTURE, 2), Ok(Some(9000)));
    assert_eq!(manifest_of(&mem), manifest_bytes(2, 0));
    assert!(mem
        .rows
        .borrow()
        .iter()
        .filter(|((ns, _), _)| *ns == DATA_NS.0)
        .all(|(_, v)| v.as_slice() == b"2:v"));
    assert_eq!(
        *mem.audit.borrow(),
        vec![Audit::RecordsEvolved {
            from: 1,
            to: 2,
            rows: 9000
        }]
    );
    assert!(!mem
        .rows
        .borrow()
        .contains_key(&(MANIFEST_NS.0, CURSOR_KEY.to_vec())));

    // Killed after the first page: manifest (1, 2) and a cursor; the next boot resumes.
    let mem = opened_store(9000);
    mem.crash_at.set(Some(2));
    assert!(evolve_once(&mem, FIXTURE, 2).is_err());
    assert_eq!(manifest_of(&mem), manifest_bytes(1, 2));
    mem.crash_at.set(None);
    assert_eq!(evolve_once(&mem, FIXTURE, 2), Ok(Some(9000)));
    assert!(
        mem.rows
            .borrow()
            .iter()
            .filter(|((ns, _), _)| *ns == DATA_NS.0)
            .all(|(_, v)| v.as_slice() == b"2:v"),
        "no row converted twice"
    );

    // A fault in the last payload page: manifest still (1, 2), the last page unconverted.
    let mem = opened_store(9000);
    mem.crash_at.set(Some(3));
    assert!(evolve_once(&mem, FIXTURE, 2).is_err());
    assert_eq!(manifest_of(&mem), manifest_bytes(1, 2));
    assert_eq!(
        mem.rows.borrow().get(&(DATA_NS.0, b"r08999".to_vec())),
        Some(&b"v".to_vec())
    );
}

/// (h) With the production table (empty): a manifest (1, tail 2) and a format-2 manifest are both
/// NEWER before any write; a current manifest is admitted with zero extra reads.
#[test]
fn the_production_chain_refuses_newer_and_reads_nothing_when_current() {
    assert!(RECORD_STEPS.is_empty());
    assert_eq!(RECORD_FORMAT, 1);
    for (format, tail) in [(1, 2), (2, 0)] {
        let mem = evolve_store(3, format, tail);
        assert_eq!(
            evolve_once(&mem, RECORD_STEPS, RECORD_FORMAT)
                .unwrap_err()
                .word(),
            "NEWER"
        );
        assert_eq!(mem.commits.get(), 0);
    }
    let mem = evolve_store(3, 1, 0);
    assert_eq!(evolve_once(&mem, RECORD_STEPS, RECORD_FORMAT), Ok(None));
    assert_eq!((mem.scans.get(), mem.commits.get()), (0, 0));
    assert!(!has_step(0) && !has_step(1));
}

fn attempt(nonce: u8, expires_at: u64) -> attempts::Attempt {
    attempts::Attempt {
        digest: [7; 32],
        nonce: [nonce; 16],
        expires_at,
        written_sha256: [9; 32],
    }
}

/// (n) Attempts: one key per session (two coexist), 5C completes this directory's own, an expired
/// one is abandoned, another node's in progress is left; a settled attempt leaves IMPORT empty, and
/// no attempt is completed for a config.yaml that was not renamed into place.
#[test]
fn attempts_end_completed_refused_or_abandoned() {
    use attempts::{begin, complete, refuse, settle, Local, Settled};
    let mem = Mem::default();
    let (a, b, c) = (attempt(1, 100), attempt(2, 100), attempt(3, 1000));
    for at in [&a, &b, &c] {
        begin(&mem, at).unwrap();
    }
    assert_eq!(
        begin(&mem, &a).unwrap_err().word(),
        "VERIFY",
        "a nonce never repeats"
    );
    assert_eq!(
        mem.import().len(),
        3,
        "byte-identical configs never share a key"
    );
    // A record step ignores attempts.
    assert_eq!(run(&mem, &NONE), Ok(None));

    let not_renamed = Local {
        stamped: false,
        nonce: Some(a.nonce),
        config_sha256: [9; 32],
    };
    assert_eq!(settle(&mem, &not_renamed, 50).unwrap(), vec![]);
    let mine = Local {
        stamped: true,
        nonce: Some(a.nonce),
        config_sha256: [9; 32],
    };
    let settled = settle(&mem, &mine, 150).unwrap();
    assert_eq!(
        settled,
        vec![
            Settled::Completed {
                digest: a.digest,
                nonce: a.nonce
            },
            Settled::Abandoned {
                digest: b.digest,
                nonce: b.nonce
            },
        ]
    );
    assert_eq!(
        mem.import().len(),
        1,
        "another node's attempt in progress is left"
    );
    assert!(refuse(&mem, &c, "LIVE_WRITER: x").unwrap());
    assert!(
        !complete(&mem, &c).unwrap(),
        "a settled attempt never completes"
    );
    assert!(mem.import().is_empty());
    assert_eq!(mem.audit.borrow().len(), 3);
}

/// The SUMMARY row round-trips, with and without core's consumed-rows tail.
#[test]
fn the_summary_row_round_trips() {
    let summary = Summary {
        physical_from: 6,
        physical_to: 7,
        tags: [
            [0, 0, 0, 0],
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [0; 4],
            [0; 4],
            [0; 4],
            [0; 4],
            [9, 9, 0, 0],
        ],
        headless_cells: 3,
        ignored: 4,
        digest: vec![1; 32],
    };
    assert_eq!(Summary::decode(&summary.encode()).unwrap(), summary);
    let mut plugin = vec![Cell::Int(6), Cell::Int(7)];
    plugin.extend((0..21).map(|_| Cell::Int(0)));
    plugin.extend([Cell::Int(0), Cell::Int(0), Cell::Blob(&[0; 32])]);
    let decoded = Summary::decode(&cells::value(&plugin)).unwrap();
    assert_eq!(decoded.tags[1], [0, 0, 0, 0]);
    assert!(Summary::decode(&cells::value(&plugin[..5])).is_err());
}

/// #319 r4 §7.3: a store whose native pages stop short of the asked count (a byte or item bound)
/// before the namespace ends, and which records whether any applied commit published a Current
/// manifest at format `intermediate`.
struct Capped<'a> {
    mem: &'a Mem,
    cap: u32,
    intermediate: Option<u32>,
    published_intermediate: Counter<bool>,
}

impl<'a> Capped<'a> {
    fn new(mem: &'a Mem, cap: u32) -> Self {
        Self {
            mem,
            cap,
            intermediate: None,
            published_intermediate: Counter::new(false),
        }
    }
}

impl RecordStore for Capped<'_> {
    fn scan(&self, ns: NamespaceId, after: Option<&[u8]>, limit: u32) -> Result<Page, StoreFail> {
        self.mem.scan(ns, after, limit.min(self.cap))
    }

    fn read(&self, ns: NamespaceId, key: &[u8]) -> Result<Option<SecureVec>, StoreFail> {
        self.mem.read(ns, key)
    }

    fn commit(&self, c: Candidate) -> Result<Committed, StoreFail> {
        let publishes = self.intermediate.is_some_and(|format| {
            c.put.iter().any(|(ns, key, value)| {
                *ns == MANIFEST_NS
                    && key.as_slice() == b"active"
                    && value.as_ref() == manifest_bytes(format, 0).as_slice()
            })
        });
        let result = self.mem.commit(c)?;
        if result == Committed::Applied && publishes {
            self.published_intermediate.set(true);
        }
        Ok(result)
    }

    fn register(&self) -> Result<(), StoreFail> {
        self.mem.register()
    }
}

fn evolve_through(
    store: &dyn FormatStore,
    mem: &Mem,
    steps: &[RecordStep],
    current: u32,
) -> Result<Option<u64>, Refusal> {
    let bytes = manifest_of(mem);
    evolve_with(
        store,
        steps,
        current,
        &Manifest {
            ns: MANIFEST_NS,
            key: b"active",
            bytes: &bytes,
            format: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            migrating_to: u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
            encode: &manifest_bytes,
        },
    )
}

fn data_values(mem: &Mem) -> Vec<Vec<u8>> {
    mem.rows
        .borrow()
        .iter()
        .filter(|((ns, _), _)| *ns == DATA_NS.0)
        .map(|(_, v)| v.clone())
        .collect()
}

/// #319 r4 §7.3: a short native page is not exhaustion. Nine rows behind a store that answers
/// two per page are all converted before the manifest reads Current, and the audit counts nine.
#[test]
fn record_format_short_page_cannot_publish_current_with_unconverted_rows() {
    let mem = opened_store(9);
    let store = Capped::new(&mem, 2);
    assert_eq!(evolve_through(&store, &mem, FIXTURE, 2), Ok(Some(9)));
    assert_eq!(manifest_of(&mem), manifest_bytes(2, 0));
    assert!(data_values(&mem).iter().all(|v| v.as_slice() == b"2:v"));
    assert_eq!(
        *mem.audit.borrow(),
        vec![Audit::RecordsEvolved {
            from: 1,
            to: 2,
            rows: 9
        }]
    );
}

fn to_three(_: NamespaceId, _: &[u8], value: &[u8]) -> Result<SecureVec, Refusal> {
    let old = value
        .strip_prefix(b"2:")
        .ok_or_else(|| Refusal::Verify("step 2 requires format-2 input".to_owned()))?;
    let mut out = b"3:".to_vec();
    out.extend_from_slice(old);
    Ok(SecureVec::from(out))
}

const CHAIN: &[RecordStep] = &[
    RecordStep {
        from: 1,
        namespaces: &[DATA_NS],
        convert: to_two,
    },
    RecordStep {
        from: 2,
        namespaces: &[DATA_NS],
        convert: to_three,
    },
];

/// #319 r4 §7.3: a 1 → 2 → 3 chain never publishes a Current format-2 manifest (a format-2 binary
/// would admit ordinary serving mid-chain); the dataset stays closed until format 3, tail 0.
#[test]
fn record_format_chain_never_publishes_intermediate_current() {
    let mem = opened_store(3);
    let mut store = Capped::new(&mem, PAGE);
    store.intermediate = Some(2);
    assert_eq!(evolve_through(&store, &mem, CHAIN, 3), Ok(Some(6)));
    assert!(
        !store.published_intermediate.get(),
        "a Current format-2 manifest admits a format-2 runtime during a target-3 migration"
    );
    assert_eq!(manifest_of(&mem), manifest_bytes(3, 0));
    assert!(data_values(&mem).iter().all(|v| v.as_slice() == b"3:v"));
    assert_eq!(
        *mem.audit.borrow(),
        vec![
            Audit::RecordsEvolved {
                from: 1,
                to: 2,
                rows: 3
            },
            Audit::RecordsEvolved {
                from: 2,
                to: 3,
                rows: 3
            },
        ]
    );
}

/// #319 r4 §7.3: payload drains through ordinary pages, then a separate zero-payload commit
/// publishes Current. A fault in that completion leaves every row converted under the nonzero
/// tail; the next run publishes once, with one audit, converting nothing twice.
#[test]
fn the_final_publication_is_an_empty_commit_after_the_payload() {
    // 9,000 rows, the step opened by admission: three pages, then the completion (commit 4).
    let mem = opened_store(9000);
    mem.crash_at.set(Some(4));
    assert!(evolve_once(&mem, FIXTURE, 2).is_err());
    assert_eq!(manifest_of(&mem), manifest_bytes(1, 2));
    assert!(data_values(&mem).iter().all(|v| v.as_slice() == b"2:v"));
    assert!(mem.audit.borrow().is_empty());
    mem.crash_at.set(None);
    assert_eq!(evolve_once(&mem, FIXTURE, 2), Ok(Some(9000)));
    assert_eq!(manifest_of(&mem), manifest_bytes(2, 0));
    assert!(data_values(&mem).iter().all(|v| v.as_slice() == b"2:v"));
    assert_eq!(
        *mem.audit.borrow(),
        vec![Audit::RecordsEvolved {
            from: 1,
            to: 2,
            rows: 9000
        }]
    );
}

/// #319 r4 §7.3: the cursor is the versioned five-cell value. The prototype three-cell cursor, or
/// any unknown version, is VERIFY before any write.
#[test]
fn a_prototype_or_unknown_cursor_is_verify_before_any_write() {
    let prototype = cells::value(&[Cell::Int(0), Cell::Blob(b""), Cell::Int(0)]);
    let unknown = cells::value(&[
        Cell::Int(2),
        Cell::Int(0),
        Cell::Int(0),
        Cell::Blob(b""),
        Cell::Blob(&[0; 8]),
    ]);
    for cursor in [prototype, unknown] {
        let mem = evolve_store(3, 1, 2);
        mem.put(MANIFEST_NS, CURSOR_KEY.to_vec(), cursor);
        assert_eq!(evolve_once(&mem, FIXTURE, 2).unwrap_err().word(), "VERIFY");
        assert_eq!(mem.commits.get(), 0);
        assert!(data_values(&mem).iter().all(|v| v.as_slice() == b"v"));
    }
}

/// #319 r4 §7.3 (and the same seam for R0): the closure pre-check reads IMPORT to its explicit
/// end, not to the first page shorter than asked.
#[test]
fn a_short_import_page_is_not_the_end_of_import() {
    let rows: Vec<_> = (1..=5)
        .map(|seq| audit_row(seq, if seq == 1 { "" } else { "h" }, "h"))
        .collect();
    let mem = store_with(&rows, [0; 8]);
    let store = Capped::new(&mem, 2);
    let report = run(&store, &NONE).unwrap().unwrap();
    assert_eq!(report.rows[usize::from(table::AUDIT)], 5);
    assert!(mem.import().is_empty(), "IMPORT drained");
}

/// The initial v1 cursor of a one-namespace step, as the kernel's opening writes it.
fn initial_cursor_bytes() -> Vec<u8> {
    cells::value(&[
        Cell::Int(1),
        Cell::Int(0),
        Cell::Int(0),
        Cell::Blob(b""),
        Cell::Blob(&[0; 8]),
    ])
}

/// A format-1 store the kernel's admission already opened for the step to 2: manifest (1, 2) and
/// the step's initial cursor (#319 r4 §6).
fn opened_store(rows: usize) -> Mem {
    assert_eq!(initial_cursor(FIXTURE, 1), Some(initial_cursor_bytes()));
    let mem = evolve_store(rows, 1, 2);
    mem.put(MANIFEST_NS, CURSOR_KEY.to_vec(), initial_cursor_bytes());
    mem
}

/// #319 r4 §6: opening a step is the kernel's one atomic transaction (dataset epoch, tail, cursor
/// and migration owner together). The driver never registers or opens a step itself: an unopened
/// older manifest is VERIFY before any call to the store.
#[test]
fn the_driver_never_opens_a_step_itself() {
    let mem = evolve_store(3, 1, 0);
    assert_eq!(evolve_once(&mem, FIXTURE, 2).unwrap_err().word(), "VERIFY");
    assert_eq!(
        (mem.commits.get(), mem.registers.get(), mem.scans.get()),
        (0, 0, 0)
    );
    assert_eq!(manifest_of(&mem), manifest_bytes(1, 0));
}

/// #319 r4 §9: the final publication carries the kernel's fresh registrar and dataset epoch, so the
/// driver never writes a Current manifest through an ordinary page commit.
#[test]
fn the_final_publication_is_not_an_ordinary_commit() {
    let mem = opened_store(5);
    let mut store = Capped::new(&mem, PAGE);
    store.intermediate = Some(2);
    assert_eq!(evolve_through(&store, &mem, FIXTURE, 2), Ok(Some(5)));
    assert!(
        !store.published_intermediate.get(),
        "an ordinary commit published the Current manifest"
    );
    assert_eq!(manifest_of(&mem), manifest_bytes(2, 0));
}

/// A store that refuses (never-uncertain, nothing applied) any commit carrying more than
/// `max` converted rows, recording the size of every candidate it was sent.
struct Refusing<'a> {
    mem: &'a Mem,
    max: usize,
    sizes: RefCell<Vec<usize>>,
}

impl Refusing<'_> {
    fn rows_in(c: &Candidate) -> usize {
        c.put.iter().filter(|(ns, _, _)| *ns == DATA_NS).count()
    }
}

/// #319 r4 §7.2: a refused page shrinks to its first half, as fresh candidates, down to one
/// complete row; every row is still converted, no applied candidate exceeds what the store took,
/// and the audit counts every row once.
#[test]
fn a_refused_page_halves_to_complete_rows_and_converts_everything() {
    let mem = opened_store(9);
    let store = Refusing {
        mem: &mem,
        max: 2,
        sizes: RefCell::new(Vec::new()),
    };
    assert_eq!(evolve_through(&store, &mem, FIXTURE, 2), Ok(Some(9)));
    assert!(data_values(&mem).iter().all(|v| v.as_slice() == b"2:v"));
    assert_eq!(manifest_of(&mem), manifest_bytes(2, 0));
    assert_eq!(
        *mem.audit.borrow(),
        vec![Audit::RecordsEvolved {
            from: 1,
            to: 2,
            rows: 9
        }]
    );
    assert_eq!(
        store.sizes.borrow().first(),
        Some(&9),
        "the first candidate carries the whole page"
    );
}

/// #319 r4 §7.2: a store that refuses even one row stops the conversion after 1 + floor(log2 n)
/// sizing candidates (9, 4, 2, 1), as STORE, with the cursor and the tail exactly as committed.
#[test]
fn a_one_row_refusal_stops_after_bounded_halving() {
    let mem = opened_store(9);
    let store = Refusing {
        mem: &mem,
        max: 0,
        sizes: RefCell::new(Vec::new()),
    };
    assert_eq!(
        evolve_through(&store, &mem, FIXTURE, 2).unwrap_err().word(),
        "STORE"
    );
    assert_eq!(*store.sizes.borrow(), vec![9, 4, 2, 1]);
    assert_eq!(manifest_of(&mem), manifest_bytes(1, 2));
    assert_eq!(
        mem.rows
            .borrow()
            .get(&(MANIFEST_NS.0, CURSOR_KEY.to_vec()))
            .cloned(),
        Some(initial_cursor_bytes())
    );
    assert!(data_values(&mem).iter().all(|v| v.as_slice() == b"v"));
}

impl RecordStore for Refusing<'_> {
    fn scan(&self, ns: NamespaceId, after: Option<&[u8]>, limit: u32) -> Result<Page, StoreFail> {
        self.mem.scan(ns, after, limit)
    }

    fn read(&self, ns: NamespaceId, key: &[u8]) -> Result<Option<SecureVec>, StoreFail> {
        self.mem.read(ns, key)
    }

    fn commit(&self, c: Candidate) -> Result<Committed, StoreFail> {
        let rows = Self::rows_in(&c);
        if rows > 0 {
            self.sizes.borrow_mut().push(rows);
        }
        if rows > self.max {
            return Ok(Committed::Refused);
        }
        self.mem.commit(c)
    }

    fn register(&self) -> Result<(), StoreFail> {
        self.mem.register()
    }
}

/// The final publication as the kernel applies it: the completion with the Current manifest.
impl FormatStore for Mem {
    fn finalize(&self, mut c: Candidate, format: u32) -> Result<Committed, StoreFail> {
        c.put.push((
            MANIFEST_NS,
            b"active".to_vec(),
            SecureVec::from(manifest_bytes(format, 0)),
        ));
        self.commit(c)
    }
}

impl FormatStore for Capped<'_> {
    fn finalize(&self, c: Candidate, format: u32) -> Result<Committed, StoreFail> {
        self.mem.finalize(c, format)
    }
}

impl FormatStore for Refusing<'_> {
    fn finalize(&self, c: Candidate, format: u32) -> Result<Committed, StoreFail> {
        self.mem.finalize(c, format)
    }
}
