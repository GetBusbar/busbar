// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT'S INSTALL RECORD IS LENT, NEVER INSTALLED (status row 82, D2; THE DESIGN l.1560: no
//! kernel `OnceLock` seam beyond the two R6 exempts). The composition root owns its
//! [`crate::preflight::RootInstall`] — its linked store rows, keyed by store key and canonical
//! name, its hook names and its axes — and lends it to every reader: the configuration it resolves,
//! the registry link, the preflight and the build. The kernel keeps no copy in a static of its own,
//! shipped or test-gated, and has no installer for one.

use std::path::{Path, PathBuf};

/// Every source file of this crate outside its test code (`tests` directories and `test_support`).
fn kernel_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the source directory reads") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            let test_code = path
                .file_name()
                .is_some_and(|n| n == "tests" || n == "test_support");
            if !test_code {
                kernel_sources(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `word` occurs in `hay` as a whole identifier.
fn has_ident(hay: &str, word: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    hay.match_indices(word).any(|(at, _)| {
        hay[..at].chars().next_back().is_none_or(|c| !ident(c))
            && hay[at + word.len()..]
                .chars()
                .next()
                .is_none_or(|c| !ident(c))
    })
}

/// The code of `line`, its trailing `//` comment struck.
fn code(line: &str) -> &str {
    line.split("//").next().unwrap_or_default()
}

/// Whether `decl` declares a `static` item (not the `'static` lifetime).
fn declares_static(decl: &str) -> bool {
    decl.match_indices("static ").any(|(at, _)| {
        decl[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '\''))
    })
}

/// Every `static` of this crate's non-test sources, gated to test builds or not, whose declaration
/// (its line and the next, for a wrapped one) names one of `words`, and every `fn` named one of
/// `fns`, as `file:line: text`.
fn holders_and_installers(words: &[&str], fns: &[&str]) -> Vec<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    kernel_sources(&src, &mut files);
    files.sort();
    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a source file reads");
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            let decl = code(line);
            let next = lines.get(n + 1).copied().map_or("", code);
            let holder = declares_static(decl)
                && words
                    .iter()
                    .any(|w| has_ident(decl, w) || has_ident(next, w));
            let installer = fns
                .iter()
                .any(|f| decl.contains(&format!("fn {f}(")) || decl.contains(&format!("fn {f}<")));
            if holder || installer {
                hits.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    hits
}

/// No static of the kernel holds the root's install record or any part of it a root hands in (its
/// rows, its hook names), and no fn installs one or reads one back: the compose owns the record and
/// lends it to each reader.
#[test]
fn the_root_install_is_lent_by_the_compose_not_held_in_a_static() {
    let hits = holders_and_installers(
        &["RootInstall", "ROOT_ROWS", "TEST_ROOT_HOOK_NAMES"],
        &["install_linked_rows", "root_rows"],
    );
    assert!(
        hits.is_empty(),
        "the kernel holds the root's install record in a static, or installs or reads one:\n{}",
        hits.join("\n")
    );
}

/// The registry link reads the record it is LENT, not one a process holds: the stand-in record's
/// linked store answers by its key through the link that record is lent to, and a record that lends
/// no store (nothing installed, [`Default`]) links none, in the same process.
#[test]
fn the_registry_link_reads_the_record_it_is_lent() {
    use crate::preflight::{linked, RootInstall};
    let stand_in = RootInstall::STAND_IN;
    let (key, ..) = stand_in.stores[0];
    assert!(
        linked(&stand_in, crate::config::Legacy::stand_in())
            .expect("the stand-in's rows link")
            .resolve(key)
            .is_some(),
        "the lent record's store `{key}` is linked"
    );
    assert!(
        linked(&RootInstall::default(), crate::config::Legacy::stand_in())
            .expect("no rows link")
            .resolve(key)
            .is_none(),
        "a record that lends no store links none, whatever another record lent"
    );
}

/// TWO APPS IN ONE PROCESS, EACH ANSWERING TO ITS OWN RATE HOLDER AND DATER: each configuration is
/// lent a record carrying a holder and dater of its own, and the governance book each build makes
/// answers to that record's — the build stages its rates with its own holder, the commit raises
/// them to its own, an accrual is dated and a ledger read priced by its own dater, and neither
/// hears or reads the other's. The rate seam reads the handle each App carries, never a holder the
/// process keeps.
///
/// RED on a kernel that reads the seam off a process-wide record (`root_rows`, a hand-in slot): both
/// builds answer to the one record the process holds — in a test build, the stand-in, which lends
/// neither half — so neither holder hears its App's rates and both books date every instant to `0`.
#[test]
fn two_apps_in_one_process_answer_to_their_own_rate_holders() {
    use crate::rate_apply::{dated_history, effective_from_at, RateApply, RateEpoch, RawRates};
    use std::sync::{Arc, Mutex};

    /// One App's holder and dater, as one object the way the root's card repricer is both: it
    /// writes down what it heard and dates every instant to its own `epoch`.
    struct Own {
        epoch: u64,
        heard: Mutex<Vec<(&'static str, i64)>>,
        history: Arc<crate::cost::History>,
    }
    impl RateApply for Own {
        fn rates_staged(&self, rates: &RawRates<'_>) -> Result<(), String> {
            self.heard
                .lock()
                .unwrap()
                .push(("staged", rates.flat_minor));
            Ok(())
        }
        fn rates_withdrawn(&self) {
            self.heard.lock().unwrap().push(("withdrawn", 0));
        }
        fn rates_applied(&self, rates: &RawRates<'_>) {
            self.heard
                .lock()
                .unwrap()
                .push(("applied", rates.flat_minor));
        }
    }
    impl RateEpoch for Own {
        fn effective_from_at(&self, _at_ms: u64) -> u64 {
            self.epoch
        }
        fn history(&self) -> Option<Arc<crate::cost::History>> {
            Some(Arc::clone(&self.history))
        }
    }
    let own = |epoch: u64| -> &'static Own {
        Box::leak(Box::new(Own {
            epoch,
            heard: Mutex::new(Vec::new()),
            history: Arc::new(crate::cost::History::opening(
                crate::cost::RateCard::absent(0),
                0,
            )),
        }))
    };
    let (a, b) = (own(1_000), own(2_000));

    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    // A configuration lent a record whose holder and dater are `holder`'s, at `fee`, built and kept
    // as a boot is.
    let build = |holder: &'static Own, fee: i64| {
        let mut cfg = crate::test_support::cfg_with_provider_api_key(
            crate::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_TWO_APPS_RATE_HOLDERS"),
        );
        cfg.per_request_fee = fee;
        cfg.root.rate_apply = Some(holder);
        cfg.root.rate_epoch = Some(holder);
        crate::test_support::build_once(cfg, None).expect("the configuration builds")
    };
    let app_a = build(a, 11);
    let app_b = build(b, 22);

    assert_eq!(
        *a.heard.lock().unwrap(),
        vec![("staged", 11), ("applied", 11)],
        "the first App's holder hears its own build's rates, staged then applied, and nothing of \
         the second's"
    );
    assert_eq!(
        *b.heard.lock().unwrap(),
        vec![("staged", 22), ("applied", 22)],
        "the second App's holder hears its own build's rates, staged then applied, and nothing of \
         the first's"
    );
    let book_a = app_a.governance.as_deref().expect("the first App's book");
    let book_b = app_b.governance.as_deref().expect("the second App's book");
    assert_eq!(
        (effective_from_at(book_a, 5), effective_from_at(book_b, 5)),
        (1_000, 2_000),
        "each App's book dates an accrual by its own dater"
    );
    assert!(
        dated_history(book_a).is_some_and(|h| Arc::ptr_eq(&h, &a.history))
            && dated_history(book_b).is_some_and(|h| Arc::ptr_eq(&h, &b.history)),
        "each App's book prices its reads through its own dater's history"
    );
}

/// TWO RECORDS IN ONE PROCESS, EACH LENDING ITS OWN AUTH ROWS AND OPERATOR WORDS (row 159,
/// kernel-identity HIGH): the linked auth rows, each carrying its plugin's door, and the operator
/// credential's words ride the record the composition root lends, so a registry linked from one
/// record serves that record's rows and a reader judges the operator credential by that record's
/// words, whatever another record in the same process lent. No static of the kernel or of the
/// identity crate holds either.
///
/// RED on a kernel that reads the rows and words off a process-wide install (the identity crate's
/// `LINKED` static, or a test hand-in beside the record): the record has no `auths` or `operator`
/// to lend, and both registries serve the one table the process holds.
#[test]
fn two_records_in_one_process_lend_their_own_auth_rows_and_operator_words() {
    use crate::preflight::{linked, RootInstall};
    use busbar_kernel_identity::operator::OperatorWords;
    let legacy = crate::config::Legacy::stand_in();
    let with_row = crate::test_support::operator_double::RECORD;
    let without_row = RootInstall {
        auths: &[],
        ..with_row
    };
    let (key, ..) = with_row.auths[0];
    assert!(
        linked(&with_row, legacy)
            .expect("the record's rows link")
            .resolve(key)
            .is_some(),
        "the registry linked from a record lending the auth row `{key}` serves it"
    );
    assert!(
        linked(&without_row, legacy)
            .expect("the record's rows link")
            .resolve(key)
            .is_none(),
        "a record lending no auth row links none, whatever another record lent"
    );
    assert_eq!(
        crate::preflight::linked_auth_names(&with_row),
        [key],
        "the record's own auth rows, by key"
    );
    assert!(crate::preflight::linked_auth_names(&without_row).is_empty());

    let other_words = RootInstall {
        operator: OperatorWords {
            provider: "another-operator",
            principal_id: "another-principal",
        },
        ..with_row
    };
    assert!(
        crate::config::names_operator(key, &with_row, legacy),
        "the operator credential is the provider its own record names"
    );
    assert!(
        !crate::config::names_operator(key, &other_words, legacy),
        "another record's words name another provider"
    );
    assert!(crate::config::names_operator(
        "another-operator",
        &other_words,
        legacy
    ));
    assert_eq!(
        crate::config::default_admin_auth_names(&other_words),
        ["another-operator"],
        "an omitted `admin_auth:` is the operator credential of the record the configuration is \
         resolved under"
    );
    assert!(crate::config::is_reserved_hook_name(
        "another-operator",
        &other_words
    ));
    assert!(!crate::config::is_reserved_hook_name(
        "another-operator",
        &with_row
    ));
}

/// No static of the kernel's non-test sources holds a linked auth row, the door type it carries, or
/// the operator credential's words, and no fn installs them (row 159, kernel-identity HIGH: the
/// type alias hid the door from the static-seam scan, so the scan here names the alias itself).
#[test]
fn no_static_holds_the_linked_auth_rows_or_the_operator_words() {
    let hits = holders_and_installers(
        &["LinkedAuth", "AuthDoor", "OperatorWords"],
        &["install_linked", "install_row", "install_root_auth"],
    );
    assert!(
        hits.is_empty(),
        "the kernel holds the root's auth rows or operator words in a static, or installs them:\n{}",
        hits.join("\n")
    );
}
