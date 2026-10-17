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

    /// The busbar tree: a root crate that links the plugin's cdylib TWIN (the logic crate reaches
    /// the default distribution through the twin's lock edge), a non-plugin git dependency, a
    /// plugin only a dev-dependency names, and a plugin behind a feature `default` does not turn on.
    /// `pin` is `(url, sha)` of the pinned plugin; `in_tree` lays the logic crate on disk too.
    fn busbar_commit(&self, pin: Option<(&str, &str)>, in_tree: Option<&str>) -> String {
        let b = self.busbar();
        let mut ws =
            String::from("[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\n");
        ws.push_str(
            "left-pad = { git = \"https://example.invalid/left-pad\", rev = \"1111111\" }\n",
        );
        ws.push_str(
            "busbar-auth-devonly = { git = \"https://example.invalid/busbar-auth-devonly\", rev = \"2222222\" }\n",
        );
        ws.push_str(
            "busbar-export-off = { git = \"https://example.invalid/busbar-export-off\", rev = \"3333333\" }\n",
        );
        let mut root_deps = String::from(
            "left-pad = { workspace = true }\nbusbar-export-off = { workspace = true, optional = true }\n",
        );
        let mut lock = String::from(
            "version = 4\n\n[[package]]\nname = \"busbar\"\nversion = \"0.1.0\"\ndependencies = [\n \"busbar-auth-devonly\",\n \"busbar-export-off\",\n \"left-pad\",\n]\n\n",
        );
        for (name, n) in [
            ("left-pad", '1'),
            ("busbar-auth-devonly", '2'),
            ("busbar-export-off", '3'),
        ] {
            let sha = n.to_string().repeat(40);
            lock.push_str(&format!(
                "[[package]]\nname = \"{name}\"\nversion = \"0.1.0\"\nsource = \"git+https://example.invalid/{name}?rev={n}{n}{n}{n}{n}{n}{n}#{sha}\"\n\n"
            ));
        }
        if let Some((url, sha)) = pin {
            ws.push_str(&format!(
                "{LOGIC} = {{ git = \"{url}\", rev = \"{sha}\" }}\n{LOGIC}-plugin = {{ git = \"{url}\", rev = \"{sha}\" }}\n"
            ));
            root_deps.push_str(&format!("{LOGIC}-plugin = {{ workspace = true }}\n"));
            lock.push_str(&format!(
                "[[package]]\nname = \"{LOGIC}\"\nversion = \"0.1.0\"\nsource = \"git+{url}?rev={sha}#{sha}\"\n\n\
                 [[package]]\nname = \"{LOGIC}-plugin\"\nversion = \"0.1.0\"\nsource = \"git+{url}?rev={sha}#{sha}\"\ndependencies = [\n \"{LOGIC}\",\n]\n\n"
            ));
        }
        write(&b, "Cargo.toml", &ws);
        write(&b, "Cargo.lock", &lock);
        write(
            &b,
            "crates/busbar/Cargo.toml",
            &format!(
                "[package]\nname = \"busbar\"\nversion = \"0.1.0\"\n\n[dependencies]\n{root_deps}\n\
                 [features]\ndefault = [\"plane-twin\"]\nplane-twin = []\nexport-off = [\"dep:busbar-export-off\"]\n\n\
                 [dev-dependencies]\nbusbar-auth-devonly = {{ workspace = true }}\n"
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

/// RED (d): ONLY A PLUGIN KIND'S LOGIC CRATE IN THE DEFAULT DISTRIBUTION IS MOUNTED. The cdylib twin,
/// a git dependency of no plugin kind, a plugin only a dev-dependency names and a plugin behind a
/// feature `default` leaves off are all `git+` packages of the lock, and none of them is mounted —
/// the three that are not the twin carry commits no repository has, so reading any of them would
/// be an error here.
#[test]
fn a_cdylib_twin_and_a_non_plugin_git_dep_are_not_mounted() {
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
    assert_eq!(pins, vec![LOGIC.to_string()]);
    let all = g.files_at("HEAD").expect("HEAD lists");
    for absent in [
        "crates/busbar-plane-demo-plugin/",
        "crates/left-pad/",
        "crates/busbar-auth-devonly/",
        "crates/busbar-export-off/",
    ] {
        assert!(
            !all.keys().any(|k| k.starts_with(absent)),
            "{absent} is not mounted"
        );
    }
    assert!(all.contains_key("crates/busbar-plane-demo/src/lib.rs"));
    assert!(
        !all.keys().any(|k| k.contains("README")),
        "only the logic crate's directory is mounted, not the plugin repo"
    );
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
