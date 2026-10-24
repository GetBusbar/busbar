//! PINNED SCOPES, PROVEN OVER REAL REPOSITORIES.
//!
//! Every claim the pin rule makes is a claim about two git trees at once — which blobs a busbar
//! commit pins, and which blobs the plugin repo holds at that pin — so these build both: a plugin
//! repo with a logic crate and its cdylib twin, a busbar repo whose `Cargo.lock` pins it, and (where
//! the test is about cargo's database) a fake `$CARGO_HOME` whose `git/db` holds a bare copy.

use super::*;
use crate::audit::{self, Git};
use crate::json_lite::{Json, Obj};

const LIB_V1: &str = "pub fn decide() -> u8 {\n    1\n}\n";
const LIB_V2: &str = "pub fn decide() -> u8 {\n    2\n}\n";
const LOGIC: &str = "busbar-plane-demo";
/// The pinned plugin's production scope, assembled rather than spelled: it names a crate only these
/// tests' scratch repos hold, and `qa-names` reads a `const` path as a scan root the tree must have.
fn scope() -> String {
    format!("crates/{LOGIC}/src")
}

struct Scratch {
    root: PathBuf,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    crate::gitp::git(dir, args).unwrap_or_else(|e| panic!("git {args:?} in {}: {e}", dir.display()))
}

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().expect("a file has a parent directory"))
        .expect("the scratch directory is creatable");
    std::fs::write(&p, body).expect("the scratch file is writable");
}

fn commit(dir: &Path, msg: &str) -> String {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-qm", msg]);
    git(dir, &["rev-parse", "HEAD"]).trim().to_string()
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let root =
            std::env::temp_dir().join(format!("xtask-audit-pinned-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("nohooks")).expect("the scratch root is creatable");
        std::fs::create_dir_all(root.join("cargo")).expect("the cargo home is creatable");
        let s = Scratch { root };
        s.init(&s.plugin());
        s.init(&s.busbar());
        s
    }

    fn init(&self, dir: &Path) {
        std::fs::create_dir_all(dir).expect("the repository directory is creatable");
        let hooks = self.root.join("nohooks");
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
            vec!["config", "uploadpack.allowAnySHA1InWant", "true"],
            vec!["config", "uploadpack.allowReachableSHA1InWant", "true"],
        ] {
            git(dir, &args);
        }
    }

    fn plugin(&self) -> PathBuf {
        self.root.join("plugin")
    }

    fn busbar(&self) -> PathBuf {
        self.root.join("busbar")
    }

    fn cargo_home(&self) -> PathBuf {
        self.root.join("cargo")
    }

    fn git(&self) -> Git {
        Git::new(self.busbar()).with_cargo_home(self.cargo_home())
    }

    /// One commit of the plugin repo: the logic crate at `plane-demo/` (NOT the busbar path — the
    /// carry-over is about content, never about where the repo keeps it) and its twin beside it.
    fn plugin_commit(&self, lib: &str) -> String {
        let p = self.plugin();
        write(
            &p,
            "plane-demo/Cargo.toml",
            &format!("[package]\nname = \"{LOGIC}\"\nversion = \"0.1.0\"\n"),
        );
        write(&p, "plane-demo/src/lib.rs", lib);
        write(
            &p,
            "plane-demo-plugin/Cargo.toml",
            &format!("[package]\nname = \"{LOGIC}-plugin\"\nversion = \"0.1.0\"\n"),
        );
        write(
            &p,
            "plane-demo-plugin/src/lib.rs",
            "pub use busbar_plane_demo::*;\n",
        );
        write(&p, "README.md", "the plugin repo\n");
        commit(&p, "plugin")
    }

    /// Cargo's database for the plugin repo, as `cargo` leaves it: a bare repository under
    /// `$CARGO_HOME/git/db/<repo>-<hash>`.
    fn fill_cargo_db(&self) {
        let db = self
            .cargo_home()
            .join("git/db/busbar-plane-demo-0123456789abcdef");
        git(
            &self.root,
            &[
                "clone",
                "-q",
                "--bare",
                self.plugin().to_str().expect("utf-8 path"),
                db.to_str().expect("utf-8 path"),
            ],
        );
    }

    /// The busbar tree with the pinned plugin linked the way the default distribution links it.
    fn busbar_commit(&self, pin: Option<(&str, &str)>, in_tree: Option<&str>) -> String {
        self.busbar_commit_linked(pin, in_tree, Link::Default)
    }

    /// The busbar tree: a root crate, a non-plugin git dependency, and the pinned plugin linked as
    /// `link` says. `pin` is `(url, sha)` of the pinned plugin; `in_tree` lays the logic crate on
    /// disk too. The lock carries what cargo would resolve for that manifest over every feature.
    fn busbar_commit_linked(
        &self,
        pin: Option<(&str, &str)>,
        in_tree: Option<&str>,
        link: Link,
    ) -> String {
        let b = self.busbar();
        let mut ws =
            String::from("[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\n");
        ws.push_str(
            "left-pad = { git = \"https://example.invalid/left-pad\", rev = \"1111111\" }\n",
        );
        let mut root_deps = String::from("left-pad = { workspace = true }\n");
        let mut dev_deps = String::new();
        let mut root_lock_deps = vec!["left-pad".to_string()];
        let mut lock = String::from("version = 4\n\n");
        let sha1 = "1".repeat(40);
        lock.push_str(&format!(
            "[[package]]\nname = \"left-pad\"\nversion = \"0.1.0\"\nsource = \"git+https://example.invalid/left-pad?rev=1111111#{sha1}\"\n\n"
        ));
        if let Some((url, sha)) = pin {
            ws.push_str(&format!(
                "{LOGIC} = {{ git = \"{url}\", rev = \"{sha}\" }}\n{LOGIC}-plugin = {{ git = \"{url}\", rev = \"{sha}\" }}\n"
            ));
            lock.push_str(&format!(
                "[[package]]\nname = \"{LOGIC}\"\nversion = \"0.1.0\"\nsource = \"git+{url}?rev={sha}#{sha}\"\n\n"
            ));
            match link {
                // The cdylib TWIN is the root's edge; the logic crate is reached through the
                // twin's own lock edge.
                Link::Default => {
                    root_deps.push_str(&format!("{LOGIC}-plugin = {{ workspace = true }}\n"));
                    root_lock_deps.push(format!("{LOGIC}-plugin"));
                    lock.push_str(&format!(
                        "[[package]]\nname = \"{LOGIC}-plugin\"\nversion = \"0.1.0\"\nsource = \"git+{url}?rev={sha}#{sha}\"\ndependencies = [\n \"{LOGIC}\",\n]\n\n"
                    ));
                }
                // `transport-webrtc`'s shape: an optional edge only a feature `default` leaves off
                // turns on.
                Link::FeatureOff => {
                    root_deps.push_str(&format!(
                        "{LOGIC} = {{ workspace = true, optional = true }}\n"
                    ));
                    root_lock_deps.push(LOGIC.to_string());
                }
                // `busbar-auth-oidc`'s shape: only a proof links it.
                Link::DevOnly => {
                    dev_deps.push_str(&format!("{LOGIC} = {{ workspace = true }}\n"));
                    root_lock_deps.push(LOGIC.to_string());
                }
            }
        }
        root_lock_deps.sort();
        let listed = root_lock_deps
            .iter()
            .map(|d| format!(" \"{d}\",\n"))
            .collect::<Vec<_>>()
            .concat();
        lock.push_str(&format!(
            "[[package]]\nname = \"busbar\"\nversion = \"0.1.0\"\ndependencies = [\n{listed}]\n"
        ));
        write(&b, "Cargo.toml", &ws);
        write(&b, "Cargo.lock", &lock);
        write(
            &b,
            "crates/busbar/Cargo.toml",
            &format!(
                "[package]\nname = \"busbar\"\nversion = \"0.1.0\"\n\n[dependencies]\n{root_deps}\n\
                 [features]\ndefault = [\"plane-twin\"]\nplane-twin = []\ndemo = [\"dep:{LOGIC}\"]\n\n\
                 [dev-dependencies]\n{dev_deps}"
            ),
        );
        write(&b, "crates/busbar/src/main.rs", "fn main() {}\n");
        // The root crate's `src/root` is a scope of its own (`derive_scopes`' split crate).
        write(&b, "crates/busbar/src/root/mod.rs", "pub fn root() {}\n");
        let crate_dir = b.join("crates").join(LOGIC);
        let _ = std::fs::remove_dir_all(&crate_dir);
        if let Some(lib) = in_tree {
            write(
                &b,
                &format!("crates/{LOGIC}/Cargo.toml"),
                &format!("[package]\nname = \"{LOGIC}\"\nversion = \"0.1.0\"\n"),
            );
            write(&b, &format!("crates/{LOGIC}/src/lib.rs"), lib);
        }
        commit(&b, "busbar")
    }

    /// The derived scope for the plugin's `src`, carrying ONE zero round read at `at`.
    fn audited_scope(&self, git: &Git, at: &str) -> Json {
        let mounted = git
            .mounted_at(at)
            .expect("the mounts at the audited commit read");
        let mut sc = audit::derive_scopes(&self.busbar(), &mounted)
            .into_iter()
            .find(|s| s.get("id").as_str() == Some(scope().as_str()))
            .unwrap_or_else(|| panic!("{} is derived", scope()));
        let files = git.files_at(at).expect("the audited commit lists");
        let hash = audit::tree_hash(&sc, &files).expect("the scope owns files");
        let o = sc.as_object_mut().expect("a scope is an object");
        o.insert("tree_hash", Json::Str(hash));
        o.insert("audited_at", Json::Str(at.to_string()));
        o.insert("round", Json::Int(1));
        o.insert("result", Json::Str("zero".to_string()));
        o.insert("counts", Json::Object(Obj::new()));
        o.insert("report", Json::Str("reports/demo.md".to_string()));
        o.insert("auditor", Json::Str("alice".to_string()));
        sc
    }

    fn register(&self, scopes: Vec<Json>) -> PathBuf {
        let path = self.root.join("audit-ledger.json");
        audit::save(&path, &audit::new_doc(scopes)).expect("the register is writable");
        path
    }
}

/// How the busbar root links the pinned plugin.
#[derive(Clone, Copy, Debug)]
enum Link {
    /// Through the default distribution (the root's normal edge to the cdylib twin).
    Default,
    /// Behind a root feature `default` does not turn on.
    FeatureOff,
    /// Through a dev-dependency only.
    DevOnly,
}

fn row_status(doc: &Json, git: &Git, id: &str) -> (&'static str, Option<String>, usize) {
    let rows = audit::rows(doc, git).expect("the rows read");
    let r = rows
        .into_iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("{id} has a row"));
    (r.status, r.pin, r.loc)
}

/// RED (a): THE PIN MOVED TO DIFFERENT CONTENT, SO THE AUDIT EXPIRED. A round read at the old pin
/// does not describe the new pin's tree, and the scope says `stale` — as any moved tree does.
#[test]
fn a_pinned_scope_whose_rev_moved_reads_stale() {
    let s = Scratch::new("stale");
    let v1 = s.plugin_commit(LIB_V1);
    let v2 = s.plugin_commit(LIB_V2);
    s.fill_cargo_db();
    let url = "https://example.invalid/GetBusbar/busbar-plane-demo";

    let at = s.busbar_commit(Some((url, &v1)), None);
    let g = s.git();
    let sc = s.audited_scope(&g, &at);
    let doc = audit::new_doc(vec![sc.clone()]);
    let (status, pin, loc) = row_status(&doc, &g, &scope());
    assert_eq!(
        status, "unconfirmed",
        "the round reads the pinned tree it was taken at"
    );
    assert_eq!(
        pin.as_deref(),
        Some(format!("pinned: GetBusbar/busbar-plane-demo@{}", &v1[..10]).as_str()),
        "the row says where its bytes came from"
    );
    assert!(
        loc > 0,
        "a pinned crate's lines are counted in its own repository"
    );

    s.busbar_commit(Some((url, &v2)), None);
    let g = s.git();
    let (status, pin, _) = row_status(&doc, &g, &scope());
    assert_eq!(
        status, "stale",
        "the pin moved to different bytes: the audit expired"
    );
    assert!(pin.is_some_and(|p| p.ends_with(&v2[..10])));
}

/// RED (b): THE CARRY-OVER. The crate leaves the tree for its own repo at a different path, byte
/// for byte, and the record taken while it lived here stays exactly as valid as it was — no
/// phantom, no missing scope, no forged stamp, and the status the round earned.
#[test]
fn a_byte_identical_pin_at_another_repo_path_keeps_the_record() {
    let s = Scratch::new("carry");
    let v1 = s.plugin_commit(LIB_V1);
    // No cargo db: the pin is produced by the fetch fallback, as on a runner whose db is cold.
    let url = format!("file://{}", s.plugin().display());

    let at = s.busbar_commit(None, Some(LIB_V1));
    let g = s.git();
    assert!(g.pins_at(&at).expect("pins read").is_empty());
    let sc = s.audited_scope(&g, &at);
    let before = sc.get("tree_hash").as_str().map(str::to_string);

    s.busbar_commit(Some((&url, &v1)), None);
    let g = s.git();
    assert!(
        !s.busbar().join("crates").join(LOGIC).exists(),
        "the crate is gone from the tree"
    );
    let now = g
        .files_at("HEAD")
        .expect("HEAD lists, with the pin mounted");
    assert_eq!(
        audit::tree_hash(&sc, &now),
        before,
        "the same bytes at the same mount path hash the same"
    );

    let mounted = g.mounted_at("HEAD").expect("the mounts read");
    let derived = audit::derive_scopes(&s.busbar(), &mounted);
    let register = s.register(audit::merge(&derived, &[sc]));
    let f = crate::audit_cmd::check(&g, &register).expect("the check reads every pin");
    assert!(f.missing.is_empty(), "missing: {:?}", f.missing);
    assert!(f.phantom.is_empty(), "phantom: {:?}", f.phantom);
    assert!(f.stamped.is_empty(), "stamped: {:?}", f.stamped);
    let doc = audit::load(&register).expect("the register parses");
    let (status, pin, _) = row_status(&doc, &g, &scope());
    assert_eq!(status, "unconfirmed", "the record carried over");
    assert!(pin.is_some());
}

/// RED (c): A PIN NOBODY CAN PRODUCE IS RED, AND SAYS WHICH. Not in any cargo db and not fetchable:
/// `--check` refuses, naming the package and the commit, rather than reading the tree without it.
#[test]
fn a_pin_that_cannot_be_produced_turns_check_red_naming_it() {
    let s = Scratch::new("unproducible");
    s.plugin_commit(LIB_V1);
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let url = format!("file://{}", s.root.join("nowhere").display());
    s.busbar_commit(Some((&url, sha)), None);
    let g = s.git();
    let register = s.register(Vec::new());
    let err = match crate::audit_cmd::check(&g, &register) {
        Ok(_) => panic!("a pin that cannot be produced must not pass"),
        Err(e) => e,
    };
    assert!(err.contains(LOGIC), "names the package: {err}");
    assert!(err.contains(sha), "names the commit: {err}");
}

/// RED (d): ONLY A PLUGIN KIND'S LOGIC CRATE IS MOUNTED — AND A PLANE'S CDYLIB TWIN BESIDE IT. A git
/// dependency of no plugin kind is a `git+` package of the lock and is not mounted (it carries a
/// commit no repository has, so reading it would be an error here). The plane's twin is mounted
/// from its logic crate's repository and commit (ARCHITECT ruling on busbar #1269: the twin's
/// `export_door!` image is audited, never by nobody).
#[test]
fn a_plane_twin_is_mounted_and_a_non_plugin_git_dep_is_not() {
    let s = Scratch::new("twin");
    let v1 = s.plugin_commit(LIB_V1);
    s.fill_cargo_db();
    s.busbar_commit(
        Some(("https://example.invalid/GetBusbar/busbar-plane-demo", &v1)),
        None,
    );
    let g = s.git();
    let pins: Vec<String> = g
        .pins_at("HEAD")
        .expect("pins read")
        .into_iter()
        .map(|p| p.package)
        .collect();
    assert_eq!(pins, vec![LOGIC.to_string(), format!("{LOGIC}-plugin")]);
    let all = g.files_at("HEAD").expect("HEAD lists");
    assert!(
        all.contains_key(&format!("crates/{LOGIC}-plugin/src/lib.rs")),
        "the plane's twin is mounted at crates/<package>-plugin"
    );
    let mounted = g.mounted_at("HEAD").expect("the mounts read");
    let derived = audit::derive_scopes(&s.busbar(), &mounted);
    assert!(
        derived
            .iter()
            .any(|sc| sc.get("id").as_str() == Some(format!("crates/{LOGIC}-plugin/src").as_str())),
        "the twin's production code is a scope of its own"
    );
    assert!(
        !all.keys().any(|k| k.starts_with("crates/left-pad/")),
        "a git dependency of no plugin kind is not mounted"
    );
    assert!(all.contains_key("crates/busbar-plane-demo/src/lib.rs"));
    assert!(
        !all.keys().any(|k| k.contains("README")),
        "only the crates' directories are mounted, not the plugin repo"
    );
}

/// RED (d2): A PLANE TWIN THE PINNED COMMIT DOES NOT CARRY IS RED, NAMING IT. The logic crate is
/// pinned and readable; its repository at that commit has no `-plugin` package, so the universe
/// refuses rather than reading the plane without its twin.
#[test]
fn a_plane_twin_the_pin_does_not_carry_is_red_naming_it() {
    let s = Scratch::new("twinless");
    s.plugin_commit(LIB_V1);
    git(&s.plugin(), &["rm", "-r", "-q", "plane-demo-plugin"]);
    let v1 = commit(&s.plugin(), "no twin");
    s.fill_cargo_db();
    s.busbar_commit(
        Some(("https://example.invalid/GetBusbar/busbar-plane-demo", &v1)),
        None,
    );
    let g = s.git();
    let err = match g.files_at("HEAD") {
        Ok(_) => panic!("a plane whose twin cannot be read must not list"),
        Err(e) => e,
    };
    assert!(
        err.contains(&format!("{LOGIC}-plugin")),
        "names the twin: {err}"
    );
    assert!(err.contains(&v1), "names the commit: {err}");
}

/// RED (e): THE TREE WINS. A pinned package whose `crates/<package>` is still on disk is read from
/// disk, never overlaid by the pin.
#[test]
fn a_pinned_package_still_in_the_tree_is_not_mounted() {
    let s = Scratch::new("tree-wins");
    let v1 = s.plugin_commit(LIB_V1);
    s.fill_cargo_db();
    s.busbar_commit(
        Some(("https://example.invalid/GetBusbar/busbar-plane-demo", &v1)),
        Some(LIB_V2),
    );
    let g = s.git();
    assert!(g.pins_at("HEAD").expect("pins read").is_empty());
    let all = g.files_at("HEAD").expect("HEAD lists");
    let tracked = git(
        &s.busbar(),
        &["rev-parse", "HEAD:crates/busbar-plane-demo/src/lib.rs"],
    );
    assert_eq!(
        all.get("crates/busbar-plane-demo/src/lib.rs")
            .map(String::as_str),
        Some(tracked.trim()),
        "the tree's own blob, not the pin's"
    );
}

/// The digest a record about the pinned plugin's `src` carries, computed BY HAND from the plugin
/// repository — the sha256 of the sorted `crates/<package>/src/<rel><TAB><blob>` lines — and never
/// through the instrument under test.
fn hand_hash(plugin: &Path, sha: &str) -> String {
    let listing = git(
        plugin,
        &["ls-tree", "-r", "--full-tree", sha, "plane-demo/src"],
    );
    let mut lines: Vec<String> = listing
        .lines()
        .filter_map(|l| {
            let (meta, path) = l.split_once('\t')?;
            let oid = meta.split_whitespace().nth(2)?;
            let rel = path.strip_prefix("plane-demo/")?;
            Some(format!("crates/{LOGIC}/{rel}\t{oid}\n"))
        })
        .collect();
    assert!(!lines.is_empty(), "the plugin's src holds files");
    lines.sort();
    let mut h = crate::sha256::Sha256::new();
    for l in &lines {
        h.update(l.as_bytes());
    }
    h.hexdigest()
}

/// The production scope over the pinned plugin's `src`, as `derive_scopes` shapes it, carrying ONE
/// zero round read at `at` whose digest is `hash`.
fn recorded_scope(at: &str, hash: &str) -> Json {
    let id = scope();
    let mut o = Obj::new();
    o.insert("id", Json::Str(id.clone()));
    o.insert("kind", Json::Str("production".to_string()));
    o.insert("paths", Json::Array(vec![Json::Str(id.clone())]));
    o.insert("tree_hash", Json::Str(hash.to_string()));
    o.insert("audited_at", Json::Str(at.to_string()));
    o.insert("round", Json::Int(1));
    o.insert("result", Json::Str("zero".to_string()));
    o.insert("counts", Json::Object(Obj::new()));
    o.insert("report", Json::Str("reports/demo.md".to_string()));
    o.insert("auditor", Json::Str("alice".to_string()));
    o.insert("fixed_at", Json::Null);
    o.insert(
        "exclude",
        Json::Array(vec![Json::Str(format!("{id}/tests"))]),
    );
    Json::Object(o)
}

/// RED (f): A PIN THE DEFAULT DISTRIBUTION LEAVES OUT IS STILL A PIN, AND ITS RECORDS ARE CHECKED
/// AGAINST IT. `busbar-transport-webrtc` sits behind `transport-webrtc`, a feature `default` does
/// not turn on, and `busbar-auth-oidc` is linked by a proof only; both are real plugins the binary
/// can link or a deployment can drop in. The pin rule used to follow the root's `default` feature,
/// so neither was mounted, their scopes hashed to `None`, and `--check` called a record carrying
/// the correct digest of the pinned bytes "not the tree at the commit they claim". A record whose
/// digest IS the pinned tree must pass, and one whose digest is not must fail, naming the scope.
#[test]
fn a_record_about_a_pin_outside_the_default_features_is_checked_against_the_pin() {
    for link in [Link::FeatureOff, Link::DevOnly] {
        let s = Scratch::new(&format!("{link:?}").to_lowercase());
        let v1 = s.plugin_commit(LIB_V1);
        let v2 = s.plugin_commit(LIB_V2);
        s.fill_cargo_db();
        let url = "https://example.invalid/GetBusbar/busbar-plane-demo";
        let at = s.busbar_commit_linked(Some((url, &v1)), None, link);
        let g = s.git();

        let pins: Vec<String> = g
            .pins_at(&at)
            .expect("pins read")
            .into_iter()
            .map(|p| p.package)
            .collect();
        assert!(
            pins.iter().any(|p| p == LOGIC),
            "{link:?}: the pin is mounted: {pins:?}"
        );

        let mounted = g.mounted_at("HEAD").expect("the mounts read");
        let derived = audit::derive_scopes(&s.busbar(), &mounted);

        // THE RIGHT DIGEST PASSES.
        let right = hand_hash(&s.plugin(), &v1);
        let register = s.register(audit::merge(&derived, &[recorded_scope(&at, &right)]));
        let f = crate::audit_cmd::check(&g, &register).expect("the check reads every pin");
        assert!(f.stamped.is_empty(), "{link:?}: stamped: {:?}", f.stamped);
        assert!(f.phantom.is_empty(), "{link:?}: phantom: {:?}", f.phantom);
        assert!(f.missing.is_empty(), "{link:?}: missing: {:?}", f.missing);
        let doc = audit::load(&register).expect("the register parses");
        let (status, pin, _) = row_status(&doc, &g, &scope());
        assert_eq!(status, "unconfirmed", "{link:?}: the record reads the pin");
        assert!(pin.is_some_and(|p| p.ends_with(&v1[..10])));

        // A WRONG DIGEST FAILS: the digest of the plugin's NEXT commit, claimed against this one.
        let wrong = hand_hash(&s.plugin(), &v2);
        assert_ne!(right, wrong);
        let register = s.register(audit::merge(&derived, &[recorded_scope(&at, &wrong)]));
        let f = crate::audit_cmd::check(&g, &register).expect("the check reads every pin");
        assert!(
            f.stamped.iter().any(|l| l.starts_with(&scope())),
            "{link:?}: a wrong digest about a non-default pin is red: {:?}",
            f.stamped
        );
    }
}
