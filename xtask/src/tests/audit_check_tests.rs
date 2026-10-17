//! `ledger --check` and `sync` against a throwaway repository with a real history: the three ways
//! the check read green over a ledger that was not clean.
//!
//! * XA1#1 — one zero at the tree of an unfixed finding let `sync --write` drop the scope;
//! * XA1#2 — a hand edit of the committed excuse list or of a scope's `paths`/`exclude`/`kind`
//!   hid a file from a `clean` scope with nothing red;
//! * XA1#3 — a register with no production scope `clean` was green.

use super::*;
use std::path::PathBuf;

struct Scratch {
    root: PathBuf,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let root =
            std::env::temp_dir().join(format!("xtask-ledger-check-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the scratch repository directory is creatable");
        let s = Scratch { root };
        let hooks = s.root.join("nohooks");
        std::fs::create_dir_all(&hooks).expect("the empty hooks directory is creatable");
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "audit@selftest"],
            vec!["config", "user.name", "audit"],
            vec!["config", "commit.gpgsign", "false"],
            vec![
                "config",
                "core.hooksPath",
                hooks.to_str().expect("utf-8 path"),
            ],
        ] {
            s.run(&args);
        }
        s
    }

    fn git(&self) -> Git {
        Git::new(&self.root)
    }

    fn run(&self, args: &[&str]) -> String {
        self.git()
            .run(args)
            .unwrap_or_else(|e| panic!("git {args:?}: {e}"))
    }

    fn write(&self, rel: &str, body: &str) {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().expect("a file has a parent directory"))
            .expect("the scratch directory is creatable");
        std::fs::write(&p, body).expect("the scratch file is writable");
    }

    fn crate_at(&self, name: &str, body: &str) {
        self.write(
            &format!("crates/{name}/Cargo.toml"),
            &format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\n"),
        );
        self.write(&format!("crates/{name}/src/lib.rs"), body);
    }

    fn commit(&self, msg: &str) {
        self.run(&["add", "-A"]);
        self.run(&["commit", "-q", "--allow-empty", "-m", msg]);
    }

    fn register(&self) -> PathBuf {
        self.root.join(audit::REGISTER_REL)
    }

    fn xtask(&self, args: &[&str]) -> i32 {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        super::main(&self.root, &owned)
    }

    /// `sync --write` and commit, twice, so the register's own scope sees itself.
    fn settle(&self) {
        for msg in ["register", "register sees itself"] {
            assert_eq!(self.xtask(&["sync", "--write"]), 0);
            self.commit(msg);
        }
    }

    fn record(&self, id: &str, round: i64, result: &str, auditor: &str, counts: &str) {
        let n = round.to_string();
        let mut args = vec![
            "record",
            "--scope",
            id,
            "--round",
            &n,
            "--result",
            result,
            "--report",
            "the module admits nothing unmetered",
            "--auditor",
            auditor,
        ];
        if !counts.is_empty() {
            args.extend(["--counts", counts]);
        }
        assert_eq!(
            self.xtask(&args),
            0,
            "`record` accepts round {round} on {id}"
        );
    }

    /// Two zero rounds from two auditors on every PRODUCTION scope: the floor, met.
    fn read_clean(&self) {
        let doc = audit::load(&self.register()).expect("the register parses");
        let ids: Vec<String> = doc
            .get("scopes")
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter(|s| s.get("kind").as_str() == Some("production"))
            .filter_map(|s| s.get("id").as_str().map(str::to_string))
            .collect();
        assert!(
            !ids.is_empty(),
            "the scratch tree derives a production scope"
        );
        for id in &ids {
            self.record(id, 1, "zero", "alice", "");
            self.record(id, 2, "zero", "bob", "");
        }
    }

    fn check(&self) -> CheckFindings {
        super::check(&self.git(), &self.register()).expect("the register can be judged")
    }

    /// Rewrite the committed register through `edit`, as a hand edit would.
    fn edit(&self, edit: impl FnOnce(&mut Obj)) {
        let mut doc = audit::load(&self.register()).expect("the register parses");
        edit(doc.as_object_mut().expect("the register is an object"));
        audit::save(&self.register(), &doc).expect("the register is writable");
    }
}

fn scope_mut<'a>(doc: &'a mut Obj, id: &str) -> &'a mut Obj {
    let Some(Json::Array(scopes)) = doc.get_mut("scopes") else {
        panic!("the register has a scopes array");
    };
    scopes
        .iter_mut()
        .find(|s| s.get("id").as_str() == Some(id))
        .and_then(Json::as_object_mut)
        .unwrap_or_else(|| panic!("{id} is in the register"))
}

/// XA1#3 RED: A REGISTER NOBODY HAS READ IS BELOW THE FLOOR. Every production scope `unaudited`
/// was green: the check measured coverage and open findings, and stated no floor at all.
#[test]
fn an_unaudited_register_is_below_the_floor() {
    let s = Scratch::new("floor-unaudited");
    s.crate_at("kernel", "pub fn admit() {}\n");
    s.crate_at("plane", "pub fn serve() {}\n");
    s.commit("base");
    s.settle();
    let f = s.check();
    assert!(
        f.gaps.is_empty() && f.missing.is_empty() && f.opens.is_empty(),
        "positive control: covered, current, nothing open"
    );
    assert!(
        f.red(),
        "no production scope has been read, so `--check` is below its floor"
    );
}

/// XA1#3 RED: ONE ZERO PER SCOPE IS `unconfirmed`, NOT CLEAN, and still below the floor.
#[test]
fn one_reading_per_scope_is_below_the_floor() {
    let s = Scratch::new("floor-one");
    s.crate_at("kernel", "pub fn admit() {}\n");
    s.commit("base");
    s.settle();
    s.record("crates/kernel/src", 1, "zero", "alice", "");
    assert!(s.check().red(), "one reader is not the floor");

    // The positive control: the second, independent reading meets it.
    s.record("crates/kernel/src", 2, "zero", "bob", "");
    let f = s.check();
    assert!(!f.red(), "every production scope clean is green");
}

/// XA1#1 RED: `sync --write` DROPPED a gone scope whose HIGH finding one zero had contradicted,
/// because the contradiction read as the answer.
#[test]
fn sync_keeps_a_gone_scope_whose_finding_one_zero_contradicted() {
    let s = Scratch::new("drop-contradicted");
    s.crate_at("keep", "pub fn k() {}\n");
    s.crate_at("gone", "pub fn g() {}\n");
    s.commit("base");
    assert_eq!(s.xtask(&["sync", "--write"]), 0);
    s.record("crates/gone/src", 1, "findings", "alice", "HIGH=1");
    s.record("crates/gone/src", 2, "zero", "bob", "");
    s.run(&["rm", "-rq", "crates/gone"]);
    s.commit("delete the crate the finding was in");
    let before = std::fs::read_to_string(s.register()).expect("the register is readable");
    assert_eq!(
        s.xtask(&["sync", "--write"]),
        1,
        "a HIGH one zero contradicted is still open, so the scope is not dropped in silence"
    );
    assert_eq!(
        std::fs::read_to_string(s.register()).expect("the register is readable"),
        before,
        "a refused sync writes nothing"
    );
}

/// XA1#1 RED: `--check` held nothing open over a HIGH that one zero at the same tree contradicted.
#[test]
fn check_holds_a_contradicted_finding_open() {
    let s = Scratch::new("contradicted");
    s.crate_at("kernel", "pub fn admit() {}\n");
    s.commit("base");
    s.settle();
    s.record("crates/kernel/src", 1, "findings", "alice", "HIGH=1");
    s.record("crates/kernel/src", 2, "zero", "bob", "");
    let f = s.check();
    assert_eq!(f.opens.len(), 1, "open: {:?}", f.opens);
    assert!(f.opens[0].contains("HIGH=1"), "{}", f.opens[0]);
}

/// XA1#2 RED, THE FINDING'S OWN CASE: a new file in a `clean` scope, hand-added to that scope's
/// `exclude` and to the excuse list. Its hash is unchanged (the file is excluded), coverage is
/// complete (the file is excused), and the scope stayed `clean` with `--check` green.
#[test]
fn a_file_hidden_by_a_hand_edited_exclude_and_excuse_is_red() {
    let s = Scratch::new("hidden");
    s.crate_at("kernel", "pub fn admit() {}\n");
    s.commit("base");
    s.settle();
    s.read_clean();
    s.commit("the readings");
    assert!(!s.check().red(), "positive control: read twice, clean");

    s.write("crates/kernel/src/new.rs", "pub fn unread() {}\n");
    s.edit(|doc| {
        let sc = scope_mut(doc, "crates/kernel/src");
        sc.insert(
            "exclude",
            Json::Array(vec![
                Json::Str("crates/kernel/src/tests".to_string()),
                Json::Str("crates/kernel/src/new.rs".to_string()),
            ]),
        );
        let Some(Json::Array(excuses)) = doc.get_mut("uncovered_by_design") else {
            panic!("the register carries the excuse list");
        };
        let mut e = Obj::new();
        e.insert("glob", Json::Str("crates/kernel/src/new.rs".to_string()));
        e.insert("reason", Json::Str("generated".to_string()));
        excuses.push(Json::Object(e));
    });
    s.commit("an unread file, hidden");
    assert!(
        s.check().red(),
        "the register's excuses and shapes are not the source's, so `--check` is red"
    );
}

/// XA1#2 RED: an excuse the source never granted is red on its own, whatever it matches.
#[test]
fn an_excuse_the_source_never_granted_is_red() {
    let s = Scratch::new("excuse");
    s.crate_at("kernel", "pub fn admit() {}\n");
    s.commit("base");
    s.settle();
    s.read_clean();
    assert!(!s.check().red(), "positive control");
    s.edit(|doc| {
        let Some(Json::Array(excuses)) = doc.get_mut("uncovered_by_design") else {
            panic!("the register carries the excuse list");
        };
        let mut e = Obj::new();
        e.insert("glob", Json::Str("crates/*/src/next.rs".to_string()));
        e.insert("reason", Json::Str("a file nobody reads".to_string()));
        excuses.push(Json::Object(e));
    });
    assert!(s.check().red());
}

/// XA1#2 RED: a scope's `exclude` or `kind` that is not the derived one is red on its own. A `kind`
/// moved off `production` takes the scope out of the floor's denominator.
#[test]
fn a_scope_shape_the_tree_does_not_derive_is_red() {
    let s = Scratch::new("shape");
    s.crate_at("kernel", "pub fn admit() {}\n");
    s.crate_at("plane", "pub fn serve() {}\n");
    s.commit("base");
    s.settle();
    s.read_clean();
    assert!(!s.check().red(), "positive control");

    s.edit(|doc| {
        scope_mut(doc, "crates/kernel/src").insert(
            "exclude",
            Json::Array(vec![
                Json::Str("crates/kernel/src/tests".to_string()),
                Json::Str("crates/kernel/src/next.rs".to_string()),
            ]),
        );
    });
    assert!(s.check().red(), "an exclude the tree does not derive");

    s.settle();
    s.read_clean();
    assert!(!s.check().red(), "sync restored the derived shape");
    s.edit(|doc| {
        scope_mut(doc, "crates/plane/src").insert("kind", Json::Str("test".to_string()));
    });
    assert!(s.check().red(), "a kind the tree does not derive");
}
