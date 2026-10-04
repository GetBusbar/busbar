//! `plugin-gates netban` and `cdeps` read the SHIPPED closure only (ARCHITECT ruling 2026-10-02):
//! normal and build dependencies for the target, no dev-dependencies. `cargo metadata`'s `resolve`
//! cannot say that: its `features` are unified across dev-dependencies, and it lists optional deps
//! a dev-dependency's feature switches on. These tests build a tiny offline fixture (path crates
//! named like the banned ones, so no registry is needed), run the real `cargo metadata` and
//! `cargo tree -e normal,build --target all --prefix none -f '{p}|{f}'` over it, and hold the
//! gates' verdicts: a dev-dependency socket crate is not reported, a normal one is.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use xtask::fleet::plugin_gates::{cdeps, netban, parse_toml, Shipped};

const POLICY: &str = r#"
[net-ban]
spec = "line 3980"
crates = ["rustls", "socket2"]
features = ["tokio/net"]
carriers = []

[c-deps]
allow = [{ crate = "native-lib-sys", version = "1.0.0", features = ["bundled"], reason = "r" }]
"#;

struct Fixture(PathBuf);

impl Fixture {
    fn new(tag: &str) -> Fixture {
        let d = std::env::temp_dir().join(format!("pg-shipped-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Fixture(d)
    }

    fn krate(&self, rel: &str, name: &str, version: &str, extra: &str) {
        let dir = self.0.join(rel);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "\n").unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n{extra}"
            ),
        )
        .unwrap();
    }

    /// The libraries every workspace points at, outside any workspace root.
    fn libs(&self) {
        self.krate("libs/socket2", "socket2", "0.5.7", "");
        self.krate("libs/rustls", "rustls", "0.23.1", "");
        self.krate(
            "libs/tokio",
            "tokio",
            "1.41.0",
            "[features]\nnet = []\nrt = []\ndefault = [\"rt\"]\n",
        );
        // an optional rustls that only the `testkit` feature switches on
        self.krate(
            "libs/helper",
            "helper",
            "0.1.0",
            "[dependencies]\nrustls = { path = \"../rustls\", optional = true }\n[features]\ntestkit = [\"dep:rustls\"]\n",
        );
    }

    /// A one-member workspace `ws/<member>` with `body` as the member's dependency tables.
    fn workspace(&self, member: &str, body: &str) -> PathBuf {
        let ws = self.0.join(format!("ws-{member}"));
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(
            ws.join("Cargo.toml"),
            format!("[workspace]\nresolver = \"2\"\nmembers = [\"{member}\"]\n"),
        )
        .unwrap();
        let dir = ws.join(member);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "\n").unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{member}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{body}"
            ),
        )
        .unwrap();
        ws
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cargo(ws: &Path, args: &[&str]) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args(args)
        .arg("--offline")
        .current_dir(ws)
        .output()
        .expect("cargo runs");
    assert!(
        out.status.success(),
        "cargo {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// What the gate gets: the metadata, and `cargo tree`'s shipped closure of the member.
fn inputs(ws: &Path, member: &str) -> (Value, Shipped) {
    let meta = cargo(ws, &["metadata", "--format-version", "1"]);
    let tree = cargo(
        ws,
        &[
            "tree",
            "--package",
            member,
            "--edges",
            "normal,build",
            "--target",
            "all",
            "--prefix",
            "none",
            "--format",
            "{p}|{f}",
        ],
    );
    (serde_json::from_str(&meta).unwrap(), Shipped::parse(&tree))
}

fn netban_of(ws: &Path, member: &str, with_tree: bool) -> Vec<String> {
    let (meta, shipped) = inputs(ws, member);
    let policy = parse_toml(POLICY).unwrap();
    netban(
        &meta,
        with_tree.then_some(&shipped),
        &policy,
        "busbar-store-x",
    )
    .unwrap()
}

#[test]
fn a_socket_crate_under_dev_dependencies_only_is_not_reported() {
    let fx = Fixture::new("dev-socket");
    fx.libs();
    let ws = fx.workspace(
        "plug",
        "[dev-dependencies]\nsocket2 = { path = \"../../libs/socket2\" }\n",
    );
    assert_eq!(netban_of(&ws, "plug", true), Vec::<String>::new());
}

#[test]
fn the_same_socket_crate_as_a_normal_dependency_is_reported() {
    let fx = Fixture::new("normal-socket");
    fx.libs();
    let ws = fx.workspace(
        "plug",
        "[dependencies]\nsocket2 = { path = \"../../libs/socket2\" }\n",
    );
    assert_eq!(
        netban_of(&ws, "plug", true),
        vec!["NETBAN socket2 0.5.7 is in the shipped closure (line 3980)".to_string()]
    );
}

/// (a) tokio is shipped without `net`; a dev-dependency turns `net` on. The resolve unifies it and
/// reads `tokio/net`; the shipped closure does not. (b) `helper` is shipped; a dev-dependency on it
/// with `testkit` pulls the optional rustls, which the resolve lists as a normal edge.
#[test]
fn a_dev_dependency_that_enables_net_or_an_optional_tls_dep_is_not_the_shipped_closure() {
    let fx = Fixture::new("dev-features");
    fx.libs();
    let ws = fx.workspace(
        "plug",
        "[dependencies]\ntokio = { path = \"../../libs/tokio\" }\nhelper = { path = \"../../libs/helper\" }\n\
         [dev-dependencies]\ntokio = { path = \"../../libs/tokio\", features = [\"net\"] }\n\
         helper = { path = \"../../libs/helper\", features = [\"testkit\"] }\n",
    );
    // RED arm: without the shipped view, the metadata alone has both false positives.
    assert_eq!(
        netban_of(&ws, "plug", false),
        vec![
            "NETBAN rustls 0.23.1 is in the shipped closure (line 3980)".to_string(),
            "NETBAN tokio/net is enabled in the shipped closure (line 3980)".to_string(),
        ]
    );
    // GREEN: with it, neither is reported.
    assert_eq!(netban_of(&ws, "plug", true), Vec::<String>::new());
}

#[test]
fn a_tokio_net_that_the_shipped_build_itself_enables_is_still_reported() {
    let fx = Fixture::new("normal-tokio-net");
    fx.libs();
    let ws = fx.workspace(
        "plug",
        "[dependencies]\ntokio = { path = \"../../libs/tokio\", features = [\"net\"] }\n",
    );
    assert_eq!(
        netban_of(&ws, "plug", true),
        vec!["NETBAN tokio/net is enabled in the shipped closure (line 3980)".to_string()]
    );
}

/// The `cdeps` gate shares the closure: a bundling feature only a dev-dependency turns on does not
/// count as bundled in the shipped build.
#[test]
fn cdeps_does_not_count_a_bundling_feature_only_a_dev_dependency_enables() {
    let meta = serde_json::json!({
        "workspace_members": ["m"],
        "packages": [
            {"id": "m", "name": "busbar-store-x", "version": "1.0.0", "source": null, "links": null},
            {"id": "n", "name": "native-lib-sys", "version": "1.0.0", "source": "registry", "links": "native"},
        ],
        "resolve": {"nodes": [
            {"id": "m", "deps": [{"pkg": "n", "dep_kinds": [{"kind": null}]}], "features": []},
            {"id": "n", "deps": [], "features": ["bundled"]},
        ]},
    });
    let policy = parse_toml(POLICY).unwrap();
    assert_eq!(cdeps(&meta, None, &policy).unwrap(), Vec::<String>::new());
    let shipped = Shipped::parse("native-lib-sys v1.0.0|default\n");
    assert_eq!(
        cdeps(&meta, Some(&shipped), &policy).unwrap(),
        vec!["CDEP native-lib-sys is not bundled: features ['bundled'] are off".to_string()]
    );
}
