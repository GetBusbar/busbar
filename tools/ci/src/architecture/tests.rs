//! Ports of test_check.py, test_compiler_{dependencies,parallel,seed,storage}.py,
//! test_generated_architecture_context.py and test_c_witness.py (the
//! confinement lifecycle cases live in confine::tests).
use super::graph::{
    self, PUBLIC_C_HEADER, check_declared, check_graph, dependency, dependency_tables,
};
use super::sources::{self, core_source_inventory, core_target_roots};
use super::witness::{self, WITNESS_SEED};
use super::*;
use crate::confine::lifecycle_tests::Fixture;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::rc::Rc;

fn parse(text: &str) -> Value {
    json::parse(text.as_bytes()).unwrap()
}

fn temp() -> TempDir {
    let path =
        pathx::resolve(&std::env::temp_dir().join(format!("architecture-{}", pathx::uuid4())));
    fs::create_dir_all(&path).unwrap();
    TempDir(path)
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn s(values: &[&str]) -> Vec<String> {
    strings(values)
}

fn policy() -> Policy {
    Policy::new(parse(
        r#"{"version": 1, "forbidden_shipping_features": ["test-support", "test-seal"],
        "core": {"busbar-contract": {"manifest": "crates/contract/Cargo.toml", "allows": []},
                 "busbar-kernel": {"manifest": "crates/kernel/Cargo.toml", "allows": ["busbar-contract"]}},
        "repositories": {"GetBusbar/busbar-auth-alpha": {"packages": [
            {"name": "busbar-auth-alpha", "manifest": "auth-alpha/Cargo.toml", "role": "implementation"},
            {"name": "busbar-auth-alpha-plugin", "manifest": "auth-alpha-plugin/Cargo.toml", "role": "wrapper"}]},
            "GetBusbar/busbar-store-beta": {"packages": [
                {"name": "busbar-store-beta", "manifest": "store-beta/Cargo.toml", "role": "implementation"}]}},
        "assembly": {"package": "busbar-default", "repository": "GetBusbar/busbar", "manifest": "dist/default/Cargo.toml"}}"#,
    ))
    .unwrap()
}

/// A policy with only the given data (`SimpleNamespace(data=...)`).
fn bare(data: Value) -> Policy {
    Policy {
        data,
        packages: Vec::new(),
    }
}

// ---- test_check.CoreSourceInventoryTests --------------------------------------

#[test]
fn sdk_nested_sources_tests_and_build_scripts_are_all_in_scope() {
    let dir = temp();
    let expected = [
        "crates/contract/src/lib.rs",
        "crates/contract/src/abi/sdk/hidden.rs",
        "crates/contract/tests/fixture.rs",
        "crates/contract/build.rs",
        "crates/kernel/src/lib.rs",
    ];
    for relative in expected {
        write(&dir.0.join(relative), "fn fixture() {}");
    }
    // Candidate/legacy file subsets cannot narrow the trusted member inventory.
    let mut p = policy();
    p.data
        .set("policy_sources", parse(r#"["crates/kernel/src/lib.rs"]"#));
    let mut want: Vec<String> = expected
        .iter()
        .map(|r| text(&pathx::resolve(&dir.0.join(r))))
        .collect();
    want.sort();
    assert_eq!(core_source_inventory(&p, &dir.0).unwrap(), want);
}

#[test]
fn a_missing_core_member_is_not_silently_unchecked() {
    let dir = temp();
    let error = core_source_inventory(&policy(), &dir.0).unwrap_err();
    assert!(error.contains("invalid core source root"), "{error}");
}

#[test]
fn symlinked_source_cannot_escape_the_candidate() {
    let dir = temp();
    let root = dir.0.join("candidate");
    for member in ["contract", "kernel"] {
        write(
            &root.join(format!("crates/{member}/src/lib.rs")),
            "fn fixture() {}",
        );
    }
    let outside = dir.0.join("outside.rs");
    fs::write(&outside, "fn fixture() {}").unwrap();
    std::os::unix::fs::symlink(&outside, root.join("crates/contract/src/escape.rs")).unwrap();
    let error = core_source_inventory(&policy(), &root).unwrap_err();
    assert!(error.contains("escapes candidate"), "{error}");
}

// ---- test_check.CoreTargetRootTests ------------------------------------------

#[test]
fn actual_custom_binary_and_test_targets_are_retained() {
    let dir = temp();
    let p = policy();
    let mut packages = Vec::new();
    let mut expected = Vec::new();
    for (name, entry) in p.core() {
        let manifest = dir.0.join(entry.at("manifest").as_str().unwrap());
        let mut targets = Vec::new();
        for relative in ["src/custom-binary.rs", "tests/custom-test.rs", "build.rs"] {
            let path = manifest.parent().unwrap().join(relative);
            write(&path, "fn main() {}");
            expected.push(text(&pathx::resolve(&path)));
            targets.push(Value::Object(vec![(
                "src_path".into(),
                Value::str(text(&path)),
            )]));
        }
        packages.push(Value::Object(vec![
            ("name".into(), Value::str(name.clone())),
            ("manifest_path".into(), Value::str(text(&manifest))),
            ("targets".into(), Value::Array(targets)),
        ]));
    }
    expected.sort();
    let metadata = Value::Object(vec![("packages".into(), Value::Array(packages.clone()))]);
    assert_eq!(core_target_roots(&p, &dir.0, &metadata).unwrap(), expected);
    // A copied graph-resolution manifest with the same package name is insufficient.
    packages[0].set(
        "manifest_path",
        Value::str(text(&dir.0.join("resolution-stub/Cargo.toml"))),
    );
    let metadata = Value::Object(vec![("packages".into(), Value::Array(packages))]);
    assert!(
        core_target_roots(&p, &dir.0, &metadata)
            .unwrap_err()
            .contains("actual manifest")
    );
}

#[test]
fn missing_core_target_metadata_refuses() {
    let dir = temp();
    let error = core_target_roots(&policy(), &dir.0, &parse(r#"{"packages": []}"#)).unwrap_err();
    assert_eq!(
        error,
        "missing actual core target metadata: ['busbar-contract', 'busbar-kernel']"
    );
}

// ---- test_check.VectorTests ---------------------------------------------------

fn vector_policy() -> Policy {
    let mut data = policy().data;
    let repositories = data.get_mut("repositories").unwrap();
    if let Value::Object(rows) = repositories {
        rows.retain(|(k, _)| k != "GetBusbar/busbar-store-beta");
    }
    let alpha = repositories.get_mut("GetBusbar/busbar-auth-alpha").unwrap();
    alpha.set("kind", "auth".into());
    alpha.set("private", false.into());
    repositories.set(
        "GetBusbar/busbar-secret-c",
        parse(r#"{"kind": "secret", "private": false, "language": "c"}"#),
    );
    Policy::new(data).unwrap()
}

type Mutation = Box<dyn Fn(&mut Value)>;

#[test]
fn complete_vector_binds_sdk_product_and_c_witness() {
    let p = vector_policy();
    let a = "a".repeat(40);
    let vector = parse(&format!(
        r#"{{"sdk": "{a}", "products": [{{"repo": "busbar-auth-alpha", "kind": "auth",
        "package": "busbar-auth-alpha-plugin", "url": "https://github.com/GetBusbar/busbar-auth-alpha",
        "commit": "{}", "lock_sha256": "{}"}}], "c_witness": {{"repo": "busbar-secret-c",
        "sdk": "{a}", "commit": "{}", "url": "https://github.com/GetBusbar/busbar-secret-c"}}}}"#,
        "b".repeat(40),
        "c".repeat(64),
        "d".repeat(40)
    ));
    let revisions = graph::vector_revisions(&p, &vector).unwrap();
    assert_eq!(
        revisions[1],
        ("GetBusbar/busbar-auth-alpha".to_owned(), "b".repeat(40))
    );
    let mutations: Vec<Mutation> = vec![
        Box::new(|v| v.set("products", Value::Array(vec![]))),
        Box::new(|v| {
            let first = v.at("products").index(0).clone();
            if let Some(Value::Array(rows)) = v.get_mut("products") {
                rows.push(first);
            }
        }),
        Box::new(|v| {
            if let Some(Value::Array(rows)) = v.get_mut("products") {
                rows[0].set("commit", "dev".into())
            }
        }),
        Box::new(|v| {
            if let Some(Value::Array(rows)) = v.get_mut("products") {
                rows[0].set("package", "busbar-auth-alpha".into())
            }
        }),
        Box::new(|v| {
            v.get_mut("c_witness")
                .unwrap()
                .set("sdk", Value::str("e".repeat(40)))
        }),
    ];
    for mutate in mutations {
        let mut changed = vector.clone();
        mutate(&mut changed);
        assert!(graph::vector_revisions(&p, &changed).is_err());
    }
}

// ---- test_check.GraphTests ------------------------------------------------------

const ROOT: &str = "/candidate";

fn fixture() -> Value {
    let a = "a".repeat(40);
    let rows = [
        (
            "impl",
            "busbar-auth-alpha",
            Value::Null,
            "/candidate/auth-alpha/Cargo.toml",
        ),
        (
            "wrapper",
            "busbar-auth-alpha-plugin",
            Value::Null,
            "/candidate/auth-alpha-plugin/Cargo.toml",
        ),
        (
            "sdk",
            "busbar-contract",
            Value::str(format!(
                "git+https://github.com/GetBusbar/busbar?rev={a}#{a}"
            )),
            "/cargo/sdk/Cargo.toml",
        ),
        (
            "lib",
            "ordinary-library",
            Value::str("registry+https://github.com/rust-lang/crates.io-index"),
            "/cargo/lib/Cargo.toml",
        ),
    ];
    let packages = rows
        .iter()
        .map(|(i, n, s, p)| {
            Value::Object(vec![
                ("id".into(), Value::str(*i)),
                ("name".into(), Value::str(*n)),
                ("source".into(), s.clone()),
                ("manifest_path".into(), Value::str(*p)),
            ])
        })
        .collect();
    let nodes = rows
        .iter()
        .map(|(i, ..)| parse(&format!(r#"{{"id": "{i}", "features": [], "deps": []}}"#)))
        .collect();
    Value::Object(vec![
        ("packages".into(), Value::Array(packages)),
        (
            "resolve".into(),
            Value::Object(vec![("nodes".into(), Value::Array(nodes))]),
        ),
    ])
}

fn nodes(m: &mut Value) -> &mut Vec<Value> {
    match m.get_mut("resolve").unwrap().get_mut("nodes").unwrap() {
        Value::Array(rows) => rows,
        _ => unreachable!(),
    }
}

fn packages_of(m: &mut Value) -> &mut Vec<Value> {
    match m.get_mut("packages").unwrap() {
        Value::Array(rows) => rows,
        _ => unreachable!(),
    }
}

fn edge(
    m: &mut Value,
    start: &str,
    target: &str,
    name: &str,
    kind: Option<&str>,
    cfg: Option<&str>,
) {
    let node = nodes(m)
        .iter_mut()
        .find(|n| n.at("id").as_str() == Some(start))
        .unwrap();
    let kind = kind.map_or(Value::Null, Value::str);
    let cfg = cfg.map_or(Value::Null, Value::str);
    if let Some(Value::Array(deps)) = node.get_mut("deps") {
        deps.push(Value::Object(vec![
            ("name".into(), Value::str(name)),
            ("pkg".into(), Value::str(target)),
            (
                "dep_kinds".into(),
                Value::Array(vec![Value::Object(vec![
                    ("kind".into(), kind),
                    ("target".into(), cfg),
                ])]),
            ),
        ]));
    }
}

fn sibling(m: &mut Value) {
    let b = "b".repeat(40);
    packages_of(m).push(parse(&format!(
        r#"{{"id": "other", "name": "busbar-store-beta", "source": "git+https://github.com/GetBusbar/busbar-store-beta?rev={b}#{b}", "manifest_path": "/cargo/beta/Cargo.toml"}}"#
    )));
    nodes(m).push(parse(r#"{"id": "other", "features": [], "deps": []}"#));
}

fn graph_check(m: &Value) -> Result<Value> {
    check_graph(
        m,
        &policy(),
        "GetBusbar/busbar-auth-alpha",
        Path::new(ROOT),
        None,
    )
}

#[test]
fn own_wrapper_sdk_and_external_library_are_permitted() {
    let mut m = fixture();
    edge(&mut m, "wrapper", "impl", "renamed", None, None);
    edge(&mut m, "impl", "sdk", "renamed", None, None);
    edge(&mut m, "impl", "lib", "renamed", None, None);
    assert_eq!(graph_check(&m).unwrap().at("classified").as_u64(), Some(3));
}

#[test]
fn renamed_transitive_sibling_is_rejected() {
    let mut m = fixture();
    sibling(&mut m);
    edge(&mut m, "impl", "lib", "renamed", None, None);
    edge(&mut m, "lib", "other", "ordinary_helper", None, None);
    assert!(
        graph_check(&m)
            .unwrap_err()
            .contains("forbidden production/build edge")
    );
}

#[test]
fn build_and_foreign_target_are_not_hidden() {
    for (kind, cfg) in [(Some("build"), None), (None, Some("cfg(windows)"))] {
        let mut m = fixture();
        sibling(&mut m);
        edge(&mut m, "impl", "other", "renamed", kind, cfg);
        assert!(
            graph_check(&m)
                .unwrap_err()
                .contains("forbidden production/build edge")
        );
    }
}

#[test]
fn dev_only_real_core_harness_does_not_enter_shipping_graph() {
    let mut m = fixture();
    sibling(&mut m);
    edge(&mut m, "impl", "other", "renamed", Some("dev"), None);
    graph_check(&m).unwrap();
}

#[test]
fn transitive_shipping_authority_feature_is_rejected() {
    let mut m = fixture();
    edge(&mut m, "impl", "lib", "renamed", None, None);
    edge(&mut m, "lib", "sdk", "renamed", None, None);
    nodes(&mut m)[2].set("features", parse(r#"["test-seal"]"#));
    assert_eq!(
        graph_check(&m).unwrap_err(),
        "shipping feature on busbar-contract: ['test-seal']"
    );
}

#[test]
fn relabelled_first_party_source_and_registry_substitution_are_rejected() {
    for (name, source) in [
        (
            "neutral",
            "git+https://github.com/GetBusbar/unclassified#abc",
        ),
        (
            "busbar-contract",
            "registry+https://github.com/rust-lang/crates.io-index",
        ),
    ] {
        let mut m = fixture();
        packages_of(&mut m)[2].set("name", name.into());
        packages_of(&mut m)[2].set("source", source.into());
        assert!(graph_check(&m).is_err());
    }
}

#[test]
fn wrong_checkout_cannot_impersonate_own_implementation() {
    let mut m = fixture();
    packages_of(&mut m)[0].set("manifest_path", "/other/auth-alpha/Cargo.toml".into());
    assert!(graph_check(&m).unwrap_err().contains("substitution"));
}

#[test]
fn missing_resolve_is_not_evidence() {
    let mut m = fixture();
    m.set("resolve", Value::Null);
    assert!(
        graph_check(&m)
            .unwrap_err()
            .contains("resolved cargo metadata")
    );
}

#[test]
fn workspace_aliases_preserve_package_and_additive_features() {
    let (name, cfg) = dependency(
        "neutral",
        &parse(r#"{"workspace": true, "features": ["extra"]}"#),
        &parse(r#"{"dependencies": {"neutral": {"package": "busbar-contract", "features": ["test-support"]}}}"#),
    )
    .unwrap();
    assert_eq!(name, "busbar-contract");
    assert_eq!(
        json::dumps(cfg.at("features"), false),
        r#"["test-support", "extra"]"#
    );
}

#[test]
fn declared_optional_target_and_build_tables_are_all_visited() {
    let manifest = parse(
        r#"{"target": {"cfg(windows)": {"build-dependencies": {"neutral": {"optional": true}}}}}"#,
    );
    let tables = dependency_tables(&manifest);
    assert!(tables.iter().any(
        |(k, t)| *k == "build" && json::dumps(t, false) == r#"{"neutral": {"optional": true}}"#
    ));
}

#[test]
fn git_sources_keep_host_and_reject_other_types() {
    assert_eq!(
        graph::git_repository(Some("git+https://GitHub.com/GetBusbar/busbar.git?rev=x#y")),
        Some((Some("github.com".into()), "GetBusbar/busbar".into()))
    );
    assert_eq!(graph::git_repository(Some("registry+https://x")), None);
    assert_eq!(
        graph::git_repository(Some("git+file:///srv/GetBusbar/busbar")),
        Some((None, "srv/GetBusbar/busbar".into()))
    );
}

// ---- test_check.DeclarationTests -------------------------------------------------

struct Declared {
    dir: TempDir,
    sdk: String,
}

impl Declared {
    fn new() -> Declared {
        let dir = temp();
        let root = &dir.0;
        let pin = "a".repeat(40);
        let sdk = format!("git = \"https://github.com/GetBusbar/busbar\", rev = \"{pin}\"");
        fs::write(root.join(".busbar-ref"), format!("{pin} 1.6.0\n")).unwrap();
        fs::write(
            root.join("Cargo.lock"),
            format!(
                "[[package]]\nname=\"busbar-contract\"\nversion=\"1.6.0\"\nsource={}",
                json::dumps(
                    &Value::str(format!(
                        "git+https://github.com/GetBusbar/busbar?rev={pin}#{pin}"
                    )),
                    false
                )
            ),
        )
        .unwrap();
        fs::write(
            root.join("Cargo.toml"),
            format!("[workspace]\nmembers=[\"auth-alpha\", \"auth-alpha-plugin\"]\n[workspace.dependencies]\nrenamed-sdk={{package=\"busbar-contract\", {sdk}}}\n"),
        )
        .unwrap();
        for (name, deps) in [
            (
                "auth-alpha",
                "[dependencies]\nrenamed-sdk={workspace=true}\n",
            ),
            (
                "auth-alpha-plugin",
                "[dependencies]\nbusbar-auth-alpha={path=\"../auth-alpha\"}\n",
            ),
        ] {
            write(
                &root.join(name).join("Cargo.toml"),
                &format!("[package]\nname=\"busbar-{name}\"\nversion=\"1.6.0\"\n{deps}"),
            );
        }
        Declared { dir, sdk }
    }

    fn check(&self) -> Result<Vec<(String, Value)>> {
        check_declared(&policy(), "GetBusbar/busbar-auth-alpha", &self.dir.0, None)
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.0.join(relative)
    }
}

#[test]
fn exact_workspace_alias_and_wrapper_are_allowed() {
    assert_eq!(Declared::new().check().unwrap().len(), 2);
}

#[test]
fn inactive_optional_target_build_alias_cannot_hide_a_sibling() {
    let d = Declared::new();
    let path = d.path("auth-alpha/Cargo.toml");
    let mut text = fs::read_to_string(&path).unwrap();
    text += &format!(
        "[target.'cfg(windows)'.build-dependencies]\nneutral={{package=\"busbar-store-beta\",optional=true,git=\"https://github.com/GetBusbar/busbar-store-beta\",rev=\"{}\"}}\n",
        "b".repeat(40)
    );
    fs::write(&path, text).unwrap();
    assert!(
        d.check()
            .unwrap_err()
            .contains("forbidden declared build edge")
    );
}

#[test]
fn workspace_feature_alias_cannot_enable_test_authority() {
    let d = Declared::new();
    let path = d.path("auth-alpha/Cargo.toml");
    let text = fs::read_to_string(&path)
        .unwrap()
        .replace("workspace=true", "workspace=true, features=[\"test-seal\"]");
    fs::write(&path, text).unwrap();
    assert!(
        d.check()
            .unwrap_err()
            .contains("shipping feature declaration")
    );
}

#[test]
fn optional_foreign_target_build_alias_cannot_enable_test_authority() {
    let d = Declared::new();
    let path = d.path("auth-alpha/Cargo.toml");
    let original = fs::read_to_string(&path).unwrap();
    for feature in ["test-seal", "test-support"] {
        for table in [
            "dependencies",
            "target.'cfg(windows)'.dependencies",
            "target.'cfg(windows)'.build-dependencies",
        ] {
            let header = if table == "dependencies" {
                "\n".to_owned()
            } else {
                format!("\n[{table}]\n")
            };
            fs::write(
                &path,
                format!(
                    "{original}{header}hidden-sdk={{package=\"busbar-contract\", optional=true, features=[\"{feature}\"], {}}}\n",
                    d.sdk
                ),
            )
            .unwrap();
            assert!(
                d.check()
                    .unwrap_err()
                    .contains("shipping feature declaration"),
                "{feature} {table}"
            );
        }
    }
    fs::write(&path, original).unwrap();
    assert_eq!(d.check().unwrap().len(), 2);
}

#[test]
fn root_patch_and_config_replacement_are_rejected() {
    let d = Declared::new();
    let path = d.path("Cargo.toml");
    let original = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        format!("{original}[patch.'https://github.com/GetBusbar/busbar']\nbusbar-contract={{path=\"replacement\"}}\n"),
    )
    .unwrap();
    assert!(d.check().unwrap_err().contains("patch substitution"));
    fs::write(&path, original).unwrap();
    write(&d.path(".cargo/config.toml"), "paths=[\"replacement\"]\n");
    assert!(d.check().unwrap_err().contains("Cargo source substitution"));
}

#[test]
fn binary_only_root_retains_its_production_edges() {
    let d = Declared::new();
    let directory = d.path("binary");
    write(&directory.join("src/main.rs"), "fn main() {}");
    write(
        &directory.join("Cargo.toml"),
        "[workspace]\n[package]\nname=\"product\"\nversion=\"0.0.0\"\n[dependencies]\nexternal={path=\"../external\"}\n",
    );
    write(&d.path("external/src/lib.rs"), "");
    write(
        &d.path("external/Cargo.toml"),
        "[package]\nname=\"external\"\nversion=\"0.0.0\"\n",
    );
    let log = Log::default();
    let mut ctx = Ctx {
        engine: None,
        evidence: None,
        log: &log,
        ci_host: None,
    };
    let entries = vec![(
        "product".to_owned(),
        parse(r#"{"manifest": "binary/Cargo.toml", "role": "core"}"#),
    )];
    let metadata =
        graph::resolve_shipping(&mut ctx, &d.dir.0, &entries, &d.path("scratch"), false).unwrap();
    let product = metadata
        .at("packages")
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p.at("name").as_str() == Some("product"))
        .unwrap();
    assert_eq!(
        product.at("manifest_path").as_str().unwrap(),
        text(&directory.join("Cargo.toml"))
    );
    let node = metadata
        .at("resolve")
        .at("nodes")
        .as_array()
        .unwrap()
        .iter()
        .find(|n| py::eq(n.at("id"), product.at("id")))
        .unwrap();
    assert_eq!(node.at("deps").as_array().unwrap().len(), 1);
    assert_eq!(
        node.at("deps").index(0).at("name").as_str(),
        Some("external")
    );
}

#[test]
fn unclassified_workspace_member_fails_closed() {
    let d = Declared::new();
    let path = d.path("Cargo.toml");
    let text = fs::read_to_string(&path).unwrap().replace(
        "\"auth-alpha-plugin\"]",
        "\"auth-alpha-plugin\", \"extra\"]",
    );
    fs::write(&path, text).unwrap();
    write(
        &d.path("extra/Cargo.toml"),
        "[package]\nname=\"innocent\"\nversion=\"0.0.0\"\n",
    );
    assert_eq!(
        d.check().unwrap_err(),
        "unclassified workspace member: extra/Cargo.toml"
    );
}

// ---- fake execution context (the Python tests' SimpleNamespace EXECUTION) ------

type RunFn<'a> = Box<dyn FnMut(&Call) -> Result<Done> + 'a>;
type OutputFn<'a> = Box<dyn FnMut(&Call) -> Result<String> + 'a>;
type PoolRunFn<'a> = Rc<RefCell<dyn FnMut(&Path, &[String]) -> Result<Done> + 'a>>;

struct Fake<'a> {
    candidate: PathBuf,
    config: Value,
    run: RunFn<'a>,
    output: OutputFn<'a>,
    /// Pool.run(child candidate, argv); cases run serially in the calling thread.
    pool: Option<PoolRunFn<'a>>,
    pool_root: PathBuf,
    events: Rc<RefCell<Vec<String>>>,
}

impl<'a> Fake<'a> {
    fn new(root: &Path, cpus: i64, memory_gib: i64) -> Fake<'a> {
        Fake {
            candidate: root.join("candidate"),
            config: parse(&format!(
                r#"{{"resources": {{"cpus": {cpus}, "memory_bytes": {}}}}}"#,
                memory_gib << 30
            )),
            run: Box::new(|_| panic!("unexpected run")),
            output: Box::new(|_| panic!("unexpected output")),
            pool: None,
            pool_root: root.to_path_buf(),
            events: Rc::default(),
        }
    }
}

impl Engine for Fake<'_> {
    fn candidate(&self) -> PathBuf {
        self.candidate.clone()
    }
    fn config(&self) -> &Value {
        &self.config
    }
    fn run(&mut self, call: &Call) -> Result<Done> {
        (self.run)(call)
    }
    fn output(&mut self, call: &Call) -> Result<String> {
        (self.output)(call)
    }
    fn pool_check(&mut self) -> Result<()> {
        Ok(())
    }
    fn pool_map(&mut self, cases: &[Case], case: &CaseFn) -> Result<()> {
        struct Child<'b>(PathBuf, PoolRunFn<'b>);
        impl Slot for Child<'_> {
            fn candidate(&self) -> PathBuf {
                self.0.clone()
            }
            fn run(&mut self, argv: &[String], _: &Path) -> Result<Done> {
                (self.1.borrow_mut())(&self.0, argv)
            }
        }
        self.events
            .borrow_mut()
            .push(format!("map {}", cases.len()));
        for (index, row) in cases.iter().enumerate() {
            let child = self
                .pool_root
                .join(format!("compiler-isolate-{index}"))
                .join("candidate");
            fs::create_dir_all(&child).unwrap();
            case(&mut Child(child, self.pool.clone().unwrap()), row)?;
        }
        Ok(())
    }
}

fn done(code: i32, stdout: &str, stderr: &str) -> Done {
    Done {
        code,
        stdout: stdout.into(),
        stderr: stderr.into(),
    }
}

fn arg<'v>(argv: &'v [String], name: &str) -> &'v str {
    &argv[argv.iter().position(|a| a == name).unwrap() + 1]
}

fn progress_rows(log: &Log) -> Vec<Value> {
    log.lines()
        .iter()
        .filter_map(|l| l.strip_prefix("architecture-progress: "))
        .map(parse)
        .collect()
}

fn witness_policy(sources: &[(&str, &str)]) -> Policy {
    let rows: Vec<Value> = sources
        .iter()
        .map(|(source, _)| {
            parse(&format!(
                r#"{{"source": "{source}", "markers": ["WITNESS"], "count": 1}}"#
            ))
        })
        .collect();
    let mut data = parse(
        r#"{"core": {"busbar-contract": {"manifest": "crates/contract/Cargo.toml"},
                    "busbar-plugin-loader": {"manifest": "crates/loader/Cargo.toml"}}}"#,
    );
    data.set("compiler_witnesses", Value::Array(rows));
    bare(data)
}

fn witness_sources(root: &Path, sources: &[(&str, &str, &str)]) {
    fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
    for (source, flags, code) in sources {
        write(
            &root.join(source),
            &format!("/// ```{flags}\n/// {code}\n/// ```\n"),
        );
    }
}

fn message(name: &str, code: Option<&str>, rendered: &str) -> String {
    let code = code.map_or("null".to_owned(), |c| format!("\"{c}\""));
    format!(
        r#"{{"reason": "compiler-message", "target": {{"name": "{name}"}}, "message": {{"level": "error", "code": {{"code": {code}}}, "rendered": "{rendered}"}}}}"#
    )
}

fn artifact(name: &str, fresh: bool) -> String {
    format!(
        r#"{{"reason": "compiler-artifact", "target": {{"name": "{name}", "kind": ["example"]}}, "fresh": {fresh}}}"#
    )
}

// ---- test_compiler_dependencies -------------------------------------------------

fn dependencies_fixture(negative: &str) -> Result<Value> {
    let dir = temp();
    let root = dir.0.clone();
    let sources = [
        (
            "crates/contract/src/positive.rs",
            "",
            "fn main() { /* WITNESS */ }",
        ),
        (
            "crates/contract/src/private.rs",
            "compile_fail,E0603",
            "use busbar_plugin_loader::private; // WITNESS",
        ),
        (
            "crates/loader/src/private.rs",
            "compile_fail,E0603",
            "// WITNESS",
        ),
        ("unknown.rs", "compile_fail,E0603", "// WITNESS"),
    ];
    witness_sources(&root, &sources);
    let policy = witness_policy(&sources.map(|(s, f, _)| (s, f)));
    let calls = RefCell::new(Vec::new());
    let negative = negative.to_owned();
    let contract = text(&root.join("crates/contract"));
    let loader = text(&root.join("crates/loader"));
    let mut fake = Fake::new(&root, 4, 6);
    fake.run = Box::new(|call| {
        let argv = &call.argv;
        let name = arg(argv, "--example").to_owned();
        calls.borrow_mut().push(name.clone());
        let manifest = read(Path::new(arg(argv, "--manifest-path"))).unwrap();
        assert_eq!(
            json::dumps(manifest.at("dependencies").at("busbar-contract"), false),
            format!(r#"{{"path": "{contract}"}}"#)
        );
        assert_eq!(
            json::dumps(
                manifest.at("dependencies").at("busbar-plugin-loader"),
                false
            ),
            format!(r#"{{"path": "{loader}", "optional": true}}"#)
        );
        assert!(call.discard && call.capture);
        assert_eq!(arg(argv, "--jobs"), "4");
        if name == "witness_00" {
            assert!(!argv.iter().any(|a| a == "--features"));
            return Ok(done(0, "", ""));
        }
        assert_eq!(arg(argv, "--features"), "busbar-plugin-loader");
        Ok(done(
            101,
            &message(&name, Some(&negative), "private item diagnostic"),
            "",
        ))
    });
    let log = Log(Some(Default::default()));
    let result = {
        let mut ctx = Ctx {
            engine: Some(&mut fake),
            evidence: None,
            log: &log,
            ci_host: None,
        };
        witness::check_compiler_witnesses(
            &mut ctx,
            &policy,
            &root,
            &root,
            &root.join("scratch"),
            false,
        )
    };
    drop(fake);
    if result.is_ok() {
        assert_eq!(
            calls.into_inner(),
            s(&["witness_00", "witness_01", "witness_02", "witness_03"])
        );
    }
    result
}

#[test]
fn contract_only_checks_skip_loader_but_private_and_unknown_sources_keep_it() {
    assert_eq!(
        json::dumps(&dependencies_fixture("E0603").unwrap(), false),
        r#"{"compiler_witnesses": 4, "production_features": true}"#
    );
}

#[test]
fn missing_crate_error_cannot_replace_the_intended_private_item_error() {
    let error = dependencies_fixture("E0432").unwrap_err();
    assert!(
        error.starts_with("witness_01: expected ['E0603'], received ['E0432']; see "),
        "{error}"
    );
}

// ---- test_compiler_parallel.ParallelSelection -------------------------------------

#[test]
fn normal_core_selects_only_the_measured_aggregate_budget() {
    let dir = temp();
    let baseline = r#"{"resources": {"cpus": 4, "memory_bytes": 6442450944, "pids": 1024},
                      "isolation": {"storage_kind": "loop-ext4", "storage_bytes": 25769803776}}"#;
    let mut configurations = vec![(parse(baseline), true)];
    for (section, key, value) in [
        ("resources", "cpus", Value::int(2)),
        ("resources", "memory_bytes", Value::int((6i64 << 30) - 1)),
        ("resources", "pids", Value::int(1023)),
        ("isolation", "storage_kind", Value::str("tmpfs")),
        ("isolation", "storage_bytes", Value::int((24i64 << 30) - 1)),
    ] {
        let mut config = parse(baseline);
        config.get_mut(section).unwrap().set(key, value);
        configurations.push((config, false));
    }
    let mut larger = parse(baseline);
    larger.set(
        "resources",
        parse(r#"{"cpus": 8, "memory_bytes": 12884901888, "pids": 2048}"#),
    );
    configurations.push((larger, true));
    let log = Log::default();
    for (config, expected) in configurations {
        let mut fake = Fake::new(&dir.0, 4, 6);
        fake.config = config;
        let ctx = Ctx {
            engine: Some(&mut fake),
            evidence: None,
            log: &log,
            ci_host: None,
        };
        assert_eq!(ctx.witness_parallel(), expected);
    }
    let ctx = Ctx {
        engine: None,
        evidence: None,
        log: &log,
        ci_host: None,
    };
    assert!(!ctx.witness_parallel());
}

#[test]
fn parallel_dispatch_keeps_the_complete_trusted_case_inventory() {
    // Inventory extraction and verdict dispatch only; no Cargo process runs.
    let root = pathx::resolve(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let policy = Policy::new(read(&root.join("ci/architecture.toml")).unwrap()).unwrap();
    let scratch = temp();
    let candidate = scratch.0.join("candidate");
    fs::create_dir(&candidate).unwrap();
    let seeds = RefCell::new(Vec::new());
    let commands: Rc<RefCell<Vec<Vec<String>>>> = Rc::default();
    let expected: Rc<RefCell<BTreeMap<String, Vec<String>>>> = Rc::default();
    let mut fake = Fake::new(&root, 4, 6);
    fake.candidate = candidate;
    fake.pool_root = scratch.0.clone();
    fake.run = Box::new(|call| {
        let argv = &call.argv;
        seeds.borrow_mut().push(argv[1].clone());
        let output = PathBuf::from(if argv[1] == "vendor" {
            argv.last().unwrap()
        } else {
            arg(argv, "--target-dir")
        });
        fs::create_dir_all(output.join("debug")).unwrap();
        if argv[1] == "vendor" {
            let setting = argv
                .iter()
                .find(|a| a.starts_with("resolver.lockfile-path="))
                .unwrap();
            let lock = PathBuf::from(
                loads(setting.split_once('=').unwrap().1)
                    .unwrap()
                    .as_str()
                    .unwrap(),
            );
            fs::create_dir_all(lock.parent().unwrap()).unwrap();
            fs::write(&lock, "version = 4\n").unwrap();
            let config = "[source.crates-io]\nreplace-with = \"vendored-sources\"\n[source.vendored-sources]\ndirectory = \"/v\"\n";
            return Ok(done(0, config, ""));
        }
        Ok(done(0, "", ""))
    });
    let (c, e) = (commands.clone(), expected.clone());
    fake.pool = Some(Rc::new(RefCell::new(move |_: &Path, argv: &[String]| {
        c.borrow_mut().push(argv.to_vec());
        let name = arg(argv, "--example").to_owned();
        let codes = e.borrow().get(&name).cloned().unwrap_or_default();
        Ok(if codes.is_empty() {
            done(0, &artifact(&name, false), "")
        } else {
            done(101, &message(&name, Some(&codes[0]), "x"), "")
        })
    })));
    // Expected codes per case come from the same trusted inventory.
    let probe = temp();
    for case in witness::prepare_cases(&policy, &root, &root, &probe.0.join("h")).unwrap() {
        expected
            .borrow_mut()
            .insert(case.name.clone(), case.expected.clone());
    }
    let inventory = witness::prepare_cases(&policy, &root, &root, &probe.0.join("i")).unwrap();
    let log = Log(Some(Default::default()));
    let receipt = {
        let mut ctx = Ctx {
            engine: Some(&mut fake),
            evidence: None,
            log: &log,
            ci_host: None,
        };
        witness::check_compiler_witnesses(&mut ctx, &policy, &root, &root, &scratch.0, true)
            .unwrap()
    };
    drop(fake);
    assert_eq!(receipt.at("compiler_witnesses").as_u64(), Some(52));
    assert_eq!(
        inventory.iter().filter(|c| c.expected.is_empty()).count(),
        16
    );
    assert_eq!(
        inventory.iter().filter(|c| !c.expected.is_empty()).count(),
        36
    );
    let commands = commands.borrow();
    assert_eq!(commands.len(), 52);
    assert_eq!(seeds.into_inner(), s(&["vendor", "check", "check"]));
    assert_eq!(
        receipt
            .at("compiler_dependency_seed")
            .at("configurations")
            .as_u64(),
        Some(2)
    );
    assert!(commands.iter().all(|argv| arg(argv, "--jobs") == "2"));
    assert_eq!(
        commands
            .iter()
            .filter(|argv| argv.iter().any(|a| a == "--features"))
            .count(),
        2
    );
}

// ---- test_compiler_seed ------------------------------------------------------------

const VENDOR_CONFIG: &str = "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.\"git+https://github.com/GetBusbar/example?rev=abc\"]\ngit = \"https://github.com/GetBusbar/example\"\nrev = \"abc\"\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"/candidate/witness-vendor\"\n";

struct SeedFixture {
    dir: TempDir,
    policy: Policy,
    vendor_returncode: i32,
    seed_returncode: i32,
    outcome: BTreeMap<String, (i32, Vec<String>)>,
}

impl SeedFixture {
    fn new() -> SeedFixture {
        let dir = temp();
        fs::create_dir(dir.0.join("candidate")).unwrap();
        let sources = [
            (
                "crates/contract/src/positive.rs",
                "",
                "fn main() { /* WITNESS */ }",
            ),
            (
                "crates/contract/src/private.rs",
                "compile_fail,E0624",
                "// WITNESS",
            ),
            (
                "crates/loader/src/private.rs",
                "compile_fail,E0603",
                "// WITNESS",
            ),
        ];
        witness_sources(&dir.0, &sources);
        let policy = witness_policy(&sources.map(|(s, f, _)| (s, f)));
        let outcome = [
            ("witness_00", (0, vec![artifact("witness_00", false)])),
            (
                "witness_01",
                (
                    101,
                    vec![message("witness_01", Some("E0624"), "diagnostic")],
                ),
            ),
            (
                "witness_02",
                (
                    101,
                    vec![message("witness_02", Some("E0603"), "diagnostic")],
                ),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        SeedFixture {
            dir,
            policy,
            vendor_returncode: 0,
            seed_returncode: 0,
            outcome,
        }
    }

    fn root(&self) -> &Path {
        &self.dir.0
    }

    /// Returns (result, events, seed calls, progress/log lines, case targets).
    fn run(
        &self,
        evidence: Option<PathBuf>,
    ) -> (Result<Value>, Vec<String>, Vec<Vec<String>>, Vec<String>) {
        let root = self.root().to_path_buf();
        let harness = root.join("scratch/compiler-witnesses");
        let events: Rc<RefCell<Vec<String>>> = Rc::default();
        let seed_calls: Rc<RefCell<Vec<Vec<String>>>> = Rc::default();
        let calls = seed_calls.clone();
        let targets: Rc<RefCell<Vec<PathBuf>>> = Rc::default();
        let mut fake = Fake::new(&root, 4, 6);
        fake.events = events.clone();
        let ev = events.clone();
        let (vendor_rc, seed_rc) = (self.vendor_returncode, self.seed_returncode);
        let h = harness.clone();
        let r = root.clone();
        fake.run = Box::new(move |call| {
            let argv = &call.argv;
            // The parent confined execution: vendor, then one check per feature set.
            assert!(call.discard);
            ev.borrow_mut().push(format!("seed {}", argv[1]));
            calls.borrow_mut().push(argv.clone());
            if argv[1] == "vendor" {
                let output = PathBuf::from(argv.last().unwrap());
                write(&output.join("dep-1.0.0/lib.rs"), "pub fn dep() {}\n");
                let setting = argv
                    .iter()
                    .find(|a| a.starts_with("resolver.lockfile-path="))
                    .unwrap();
                let lock = PathBuf::from(
                    loads(setting.split_once('=').unwrap().1)
                        .unwrap()
                        .as_str()
                        .unwrap(),
                );
                fs::create_dir_all(lock.parent().unwrap()).unwrap();
                fs::write(&lock, "version = 4\n").unwrap();
                return Ok(done(vendor_rc, VENDOR_CONFIG, "vendor log"));
            }
            assert_eq!(arg(argv, "--example"), WITNESS_SEED);
            // Every seeded invocation receives the vendor resolution via the harness.
            assert_eq!(
                fs::read_to_string(h.join("Cargo.lock")).unwrap(),
                "version = 4\n"
            );
            assert_eq!(arg(argv, "--jobs"), "4");
            let target = PathBuf::from(arg(argv, "--target-dir"));
            assert!(target.starts_with(r.join("candidate")));
            for relative in [
                "deps/libdep-1.rmeta",
                ".fingerprint/dep-1/lib-dep",
                // A forged harness fingerprint and cached example must not survive.
                ".fingerprint/architecture-compiler-witnesses-1/example-witness_00",
                "examples/witness_seed-1.rmeta",
                "incremental/witness_seed-1/s",
            ] {
                write(&target.join("debug").join(relative), relative);
            }
            Ok(done(seed_rc, "", "seed log"))
        });
        let outcome = self.outcome.clone();
        let (ev, t, h, r) = (
            events.clone(),
            targets.clone(),
            harness.clone(),
            root.clone(),
        );
        fake.pool = Some(Rc::new(RefCell::new(
            move |child: &Path, argv: &[String]| {
                let name = arg(argv, "--example").to_owned();
                ev.borrow_mut().push(format!("case {name}"));
                let (code, messages) = outcome[&name].clone();
                if !argv.iter().any(|a| a == "--target-dir") {
                    // Unseeded fallback: exactly the original inputs and command.
                    assert!(!argv.iter().any(|a| a == "--config"));
                    assert!(!h.join("Cargo.lock").exists());
                    assert!(!h.join(format!("examples/{WITNESS_SEED}.rs")).exists());
                    assert_eq!(fs::read_dir(r.join("candidate")).unwrap().count(), 0);
                    return Ok(done(code, &messages.join("\n"), ""));
                }
                assert!(h.join("Cargo.lock").is_file());
                let target = PathBuf::from(arg(argv, "--target-dir"));
                let config = PathBuf::from(arg(argv, "--config"));
                assert!(target.starts_with(child));
                assert_eq!(
                    fs::read_to_string(target.join("debug/deps/libdep-1.rmeta")).unwrap(),
                    "deps/libdep-1.rmeta"
                );
                assert!(!target.join("debug/examples").exists());
                assert!(!target.join("debug/incremental").exists());
                assert!(
                    pathx::glob(
                        &target.join("debug/.fingerprint"),
                        "architecture-compiler-witnesses-*"
                    )
                    .is_empty()
                );
                let seed_vendor = text(&r.join("scratch/compiler-witness-seed/vendor"));
                assert!(fs::read_to_string(&config).unwrap().contains(&seed_vendor));
                for other in t.borrow().iter() {
                    assert_ne!(other, &target);
                    assert!(!target.starts_with(other.parent().unwrap()));
                }
                t.borrow_mut().push(target.clone());
                // A case writing to its copy cannot reach the seed or later cases.
                fs::write(
                    target.join("debug/deps/libdep-1.rmeta"),
                    format!("poisoned by {name}"),
                )
                .unwrap();
                Ok(done(code, &messages.join("\n"), ""))
            },
        )));
        let log = Log(Some(Default::default()));
        let result = {
            let mut ctx = Ctx {
                engine: Some(&mut fake),
                evidence,
                log: &log,
                ci_host: None,
            };
            witness::check_compiler_witnesses(
                &mut ctx,
                &self.policy,
                &root,
                &root,
                &root.join("scratch"),
                true,
            )
        };
        drop(fake);
        let events = events.borrow().clone();
        assert_eq!(
            targets
                .borrow()
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            targets.borrow().len()
        );
        let calls = seed_calls.borrow().clone();
        (result, events, calls, log.lines())
    }
}

#[test]
fn seed_is_built_once_before_cases_and_each_case_gets_a_private_copy() {
    let f = SeedFixture::new();
    let (result, events, _, _) = f.run(None);
    let receipt = result.unwrap();
    assert_eq!(receipt.at("compiler_witnesses").as_u64(), Some(3));
    let seed = receipt.at("compiler_dependency_seed");
    assert_eq!(seed.at("configurations").as_u64(), Some(2));
    assert_eq!(seed.at("status").as_str(), Some("seeded"));
    assert_eq!(
        events,
        s(&[
            "seed vendor",
            "seed check",
            "seed check",
            "map 3",
            "case witness_00",
            "case witness_01",
            "case witness_02"
        ])
    );
    let root = f.root().join("scratch/compiler-witness-seed");
    // The seed is released only after every case has finished.
    assert!(!root.join("target").exists() && !root.join("vendor").exists());
    // Candidate-side seed outputs are removed once snapshotted.
    assert_eq!(fs::read_dir(f.root().join("candidate")).unwrap().count(), 0);
    let config = fs::read_to_string(root.join("vendor.toml")).unwrap();
    assert!(config.contains("git+https://github.com/GetBusbar/example?rev=abc"));
    assert!(!config.contains("/candidate/witness-vendor"));
}

#[test]
fn seed_superset_configuration_is_built_first() {
    let f = SeedFixture::new();
    let (result, _, calls, _) = f.run(None);
    result.unwrap();
    // Superset (loader) configuration first, then the contract-only one.
    assert!(calls[1].iter().any(|a| a == "--features"));
    assert!(!calls[2].iter().any(|a| a == "--features"));
}

#[test]
fn a_seeded_positive_must_compile_its_own_crate() {
    // Exit 0 with a cached (fresh) or absent own-crate artifact is not success.
    for messages in [
        vec![artifact("witness_00", true)],
        vec![],
        vec![artifact("witness_seed", false)],
    ] {
        let mut f = SeedFixture::new();
        f.outcome.insert("witness_00".into(), (0, messages));
        let error = f.run(None).0.unwrap_err();
        assert!(
            error.starts_with("witness_00: expected successful positive control"),
            "{error}"
        );
    }
}

#[test]
fn negative_verdicts_are_unchanged() {
    let mut f = SeedFixture::new();
    f.outcome.insert(
        "witness_01".into(),
        (
            101,
            vec![message("witness_01", Some("E0001"), "diagnostic")],
        ),
    );
    let error = f.run(None).0.unwrap_err();
    assert!(
        error.starts_with("witness_01: expected ['E0624'], received ['E0001']"),
        "{error}"
    );
    let mut f = SeedFixture::new();
    f.outcome.insert(
        "witness_02".into(),
        (0, vec![artifact("witness_02", false)]),
    );
    assert!(
        f.run(None)
            .0
            .unwrap_err()
            .starts_with("witness_02: expected")
    );
}

#[test]
fn seed_failure_falls_back_to_unseeded_cases_with_the_same_verdicts() {
    for (vendor, log_name, line) in [
        (true, "vendor.log", "vendor log"),
        (false, "seed-loader.log", "seed log"),
    ] {
        let mut f = SeedFixture::new();
        if vendor {
            f.vendor_returncode = 101;
        } else {
            f.seed_returncode = 101;
        }
        let evidence = temp();
        let (result, events, _, lines) = f.run(Some(evidence.0.clone()));
        let receipt = result.unwrap();
        assert_eq!(receipt.at("compiler_witnesses").as_u64(), Some(3));
        let seed = receipt.at("compiler_dependency_seed");
        assert_eq!(
            (seed.at("status").as_str(), seed.at("fallback").as_str()),
            (Some("failed"), Some("unseeded"))
        );
        assert!(seed.at("reason").as_str().unwrap().contains(&format!(
            "compiler dependency seed failed: {}",
            log_name.trim_end_matches(".log")
        )));
        let cases: Vec<&String> = events.iter().filter(|e| e.starts_with("case ")).collect();
        assert_eq!(
            cases,
            ["case witness_00", "case witness_01", "case witness_02"]
        );
        assert!(lines.contains(&format!("compiler-seed-log: {line}")));
        assert_eq!(
            seed.at("log").as_str().unwrap(),
            format!("architecture-compiler-seed-{log_name}")
        );
        assert!(evidence.0.join(seed.at("log").as_str().unwrap()).is_file());
    }
}

#[test]
fn unseeded_fallback_keeps_negative_and_positive_failures() {
    for outcome in [
        (0, vec![artifact("witness_01", false)]),
        (
            101,
            vec![message("witness_01", Some("E0001"), "diagnostic")],
        ),
    ] {
        let mut f = SeedFixture::new();
        f.seed_returncode = 101;
        f.outcome.insert("witness_01".into(), outcome);
        assert!(
            f.run(None)
                .0
                .unwrap_err()
                .starts_with("witness_01: expected")
        );
    }
    // The strict own-artifact rule applies only to seeded cases.
    let mut f = SeedFixture::new();
    f.seed_returncode = 101;
    f.outcome.insert("witness_00".into(), (0, vec![]));
    assert_eq!(
        f.run(None).0.unwrap().at("compiler_witnesses").as_u64(),
        Some(3)
    );
}

#[test]
fn candidate_seed_links_are_rejected() {
    let dir = temp();
    let source = dir.0.join("output");
    fs::create_dir_all(source.join("debug")).unwrap();
    fs::write(dir.0.join("Cargo.toml"), "").unwrap();
    std::os::unix::fs::symlink(dir.0.join("Cargo.toml"), source.join("debug/escape")).unwrap();
    match witness::copy_candidate_tree(&source, &dir.0.join("copy")) {
        Err(witness::SeedError::Fallback(message, _)) => {
            assert!(message.contains("non-regular"), "{message}")
        }
        _ => panic!("candidate link accepted"),
    }
}

#[test]
fn vendor_configuration_cannot_add_other_settings() {
    for config in [
        format!("[build]\nrustflags = [\"-Zx\"]\n{VENDOR_CONFIG}"),
        VENDOR_CONFIG.replace("rev = \"abc\"", "rev = \"abc\"\nlocal-registry = \"/x\""),
        "[source.crates-io]\nreplace-with = \"other\"\n[source.vendored-sources]\ndirectory = \"/x\"\n".into(),
        "[source.crates-io]\nreplace-with = \"vendored-sources\"\n".into(),
    ] {
        assert!(matches!(
            witness::vendor_source_config(&config, Path::new("/seed/vendor")),
            Err(witness::SeedError::Fallback(..))
        ));
    }
    let emitted = match witness::vendor_source_config(VENDOR_CONFIG, Path::new("/seed/vendor")) {
        Ok(text) => text,
        Err(_) => panic!("vendor configuration refused"),
    };
    assert_eq!(
        emitted,
        "[source.\"crates-io\"]\n\"replace-with\" = \"vendored-sources\"\n[source.\"git+https://github.com/GetBusbar/example?rev=abc\"]\n\"git\" = \"https://github.com/GetBusbar/example\"\n\"rev\" = \"abc\"\n\"replace-with\" = \"vendored-sources\"\n[source.vendored-sources]\ndirectory = \"/seed/vendor\"\n"
    );
}

// ---- test_compiler_storage.CompilerWitnessStorage -------------------------------------

#[test]
fn check_jobs_are_bounded_by_candidate_cpu_and_existing_memory() {
    let dir = temp();
    let log = Log::default();
    for (cpus, memory, expected) in [(4, 6, 4), (2, 6, 2), (16, 6, 4), (4, 3, 1)] {
        let mut fake = Fake::new(&dir.0, cpus, memory);
        let ctx = Ctx {
            engine: Some(&mut fake),
            evidence: None,
            log: &log,
            ci_host: None,
        };
        assert_eq!(ctx.check_jobs(), Some(expected));
    }
    let ctx = Ctx {
        engine: None,
        evidence: None,
        log: &log,
        ci_host: None,
    };
    assert_eq!(ctx.check_jobs(), None);
}

fn storage_fixture(outcome: (i32, Option<&str>, &str)) -> Result<Value> {
    let dir = temp();
    let root = dir.0.clone();
    fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(
        root.join("witness.rs"),
        "/// ```rust\n/// fn main() { /* marker */ }\n/// ```\n/// ```compile_fail,E0624\n/// fn main() { /* marker */ }\n/// ```\n",
    )
    .unwrap();
    let policy = bare(parse(
        r#"{"core": {"busbar-contract": {"manifest": "busbar-contract/Cargo.toml"},
                    "busbar-plugin-loader": {"manifest": "busbar-plugin-loader/Cargo.toml"}},
            "compiler_witnesses": [{"source": "witness.rs", "markers": ["marker"], "count": 2}]}"#,
    ));
    let calls: Rc<RefCell<Vec<Call>>> = Rc::default();
    let mut fake = Fake::new(&root, 4, 6);
    let outcome = (
        outcome.0,
        outcome.1.map(str::to_owned),
        outcome.2.to_owned(),
    );
    let (seen, expect) = (calls.clone(), outcome.clone());
    fake.run = Box::new(move |call| {
        seen.borrow_mut().push(call.clone());
        let name = arg(&call.argv, "--example").to_owned();
        let (code, error, target) = if name == "witness_00" {
            (0, None, name.clone())
        } else {
            expect.clone()
        };
        let stdout = error
            .as_deref()
            .map(|e| message(&target, Some(e), "retained diagnostic"))
            .unwrap_or_default();
        Ok(done(code, &stdout, "retained stderr"))
    });
    let log = Log(Some(Default::default()));
    let result = {
        let mut ctx = Ctx {
            engine: Some(&mut fake),
            evidence: None,
            log: &log,
            ci_host: None,
        };
        witness::check_compiler_witnesses(
            &mut ctx,
            &policy,
            &root,
            &root,
            &root.join("scratch"),
            false,
        )
    };
    drop(fake);
    let calls = calls.borrow().clone();
    for call in &calls {
        assert!(call.discard);
        assert!(call.argv.iter().any(|a| a == "--message-format=json"));
        assert_eq!(&call.argv[..2], ["cargo", "check"]);
        assert_eq!(arg(&call.argv, "--jobs"), "4");
    }
    assert_eq!(calls.len(), 2);
    assert!(
        fs::read_to_string(root.join("scratch/compiler-witnesses/witness_01.log"))
            .unwrap()
            .contains("retained stderr")
    );
    let rows = progress_rows(&log);
    let events: Vec<&str> = rows
        .iter()
        .map(|r| r.at("event").as_str().unwrap())
        .collect();
    assert_eq!(events, ["start", "finish", "start", "finish"]);
    let cases: Vec<&str> = rows
        .iter()
        .map(|r| r.at("case").as_str().unwrap())
        .collect();
    assert_eq!(
        cases,
        ["witness_00", "witness_00", "witness_01", "witness_01"]
    );
    assert!(rows.iter().all(|r| r.at("build_jobs").as_u64() == Some(4)));
    let last = rows.last().unwrap();
    assert_eq!(
        last.at("passed").as_bool(),
        Some(outcome.0 == 1 && outcome.1.as_deref() == Some("E0624") && outcome.2 == "witness_01")
    );
    assert_eq!(last.at("log_sha256").as_str().unwrap().len(), 64);
    result
}

#[test]
fn positive_and_expected_negative_keep_their_verdicts_and_logs() {
    assert_eq!(
        json::dumps(
            &storage_fixture((1, Some("E0624"), "witness_01")).unwrap(),
            false
        ),
        r#"{"compiler_witnesses": 2, "production_features": true}"#
    );
}

#[test]
fn wrong_negative_error_code_or_target_is_still_rejected() {
    for outcome in [
        (1, Some("E0001"), "witness_01"),
        (1, Some("E0624"), "dependency"),
        (0, None, "witness_01"),
    ] {
        assert!(storage_fixture(outcome).unwrap_err().contains("expected"));
    }
}

// ---- test_compiler_storage.SourceMaterialization -----------------------------------------

fn materialization(
    failure: Option<&str>,
    repository: &str,
    cpus: i64,
    memory: i64,
    expected_jobs: i64,
) -> Result<Value> {
    let dir = temp();
    let root = dir.0.clone();
    let (checkout, trusted, candidate, scratch) = (
        root.join("checkout"),
        root.join("trusted"),
        root.join("candidate"),
        root.join("scratch"),
    );
    let krate = checkout.join("crates/core");
    let source = krate.join("custom-main.rs");
    write(
        &source,
        "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));",
    );
    let build_script = krate.join("build.rs");
    fs::write(&build_script, "fn main() {}").unwrap();
    fs::write(
        krate.join("Cargo.toml"),
        "[package]\nname=\"busbar-core\"\n",
    )
    .unwrap();
    write(
        &trusted.join("crates/busbar-contract/tests/architecture_surface.rs"),
        "// trusted source scan",
    );
    fs::write(
        trusted.join("Cargo.toml"),
        "[workspace.dependencies]\nsyn=\"2\"\nquote=\"1\"\nproc-macro2=\"1\"\nserde_json=\"1\"\n",
    )
    .unwrap();
    let output = candidate.join("target/build/core/out");
    fs::create_dir_all(&output).unwrap();
    let generated = output.join("generated.rs");
    fs::write(&generated, "fn main() {}").unwrap();
    let mut reported = output.clone();
    match failure {
        Some("escaping-output") => reported = trusted.clone(),
        Some("symlink-source") => {
            fs::remove_file(&generated).unwrap();
            std::os::unix::fs::symlink(&source, &generated).unwrap();
        }
        _ => {}
    }
    let is_core = repository == CORE;
    let entry = parse(&format!(
        r#"{{"manifest": "crates/core/Cargo.toml", "repository": "{repository}", "role": "{}"}}"#,
        if is_core { "core" } else { "implementation" }
    ));
    let mut data = parse(r#"{"core": {}, "repositories": {}}"#);
    data.get_mut("core")
        .unwrap()
        .set("busbar-core", entry.clone());
    let policy = Policy {
        data,
        packages: vec![("busbar-core".into(), entry)],
    };
    let metadata = parse(&format!(
        r#"{{"packages": [{{"id": "core-id", "name": "busbar-core", "manifest_path": "{}",
        "targets": [{{"kind": ["{}"], "src_path": "{}"}}, {{"kind": ["custom-build"], "src_path": "{}"}}]}}]}}"#,
        text(&krate.join("Cargo.toml")),
        if is_core { "bin" } else { "lib" },
        text(&source),
        text(&build_script)
    ));
    let scanned: Rc<RefCell<i32>> = Rc::default();
    let mut fake = Fake::new(&root, cpus, memory);
    fake.candidate = candidate.clone();
    let (m, c, s2) = (metadata.clone(), checkout.clone(), scratch.clone());
    let failure_owned = failure.map(str::to_owned);
    fake.output = Box::new(move |call| {
        let argv = &call.argv;
        if argv[1] == "metadata" {
            return Ok(json::dumps(&m, false));
        }
        let mut expected = if is_core {
            s(&[
                "cargo",
                "check",
                "--workspace",
                "--manifest-path",
                &text(&c.join("Cargo.toml")),
            ])
        } else {
            s(&[
                "cargo",
                "build",
                "--manifest-path",
                &text(&s2.join("shipping-probe/Cargo.toml")),
            ])
        };
        if is_core {
            expected.extend(["--jobs".into(), expected_jobs.to_string()]);
        }
        expected.push("--message-format=json".into());
        assert_eq!(argv, &expected);
        if failure_owned.as_deref() == Some("compiler-failure") {
            return Err(pathx::called_process_error(argv, 1));
        }
        Ok(format!(
            "{}\n",
            json::dumps(
                &parse(&format!(
                    r#"{{"reason": "build-script-executed", "package_id": "core-id", "out_dir": "{}"}}"#,
                    text(&reported)
                )),
                false
            )
        ))
    });
    let (k, o, src, bs, g) = (
        krate.clone(),
        output.clone(),
        source.clone(),
        build_script.clone(),
        generated.clone(),
    );
    let counter = scanned.clone();
    fake.run = Box::new(move |call| {
        *counter.borrow_mut() += 1;
        assert_eq!(
            &call.argv[call.argv.len() - 2..],
            ["--test", "architecture_surface"]
        );
        assert!(call.check);
        let env = call.env.as_ref().unwrap();
        let dirs = loads(&fs::read_to_string(&env["BUSBAR_ARCHITECTURE_GENERATED_DIRS"]).unwrap())
            .unwrap();
        assert_eq!(
            json::dumps(&dirs, false),
            format!(r#"{{"{}": "{}"}}"#, text(&k), text(&o))
        );
        if is_core {
            let inventory =
                loads(&fs::read_to_string(&env["BUSBAR_ARCHITECTURE_POLICY_SOURCES"]).unwrap())
                    .unwrap();
            let set = |key: &str| -> std::collections::BTreeSet<String> {
                inventory
                    .at(key)
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_owned())
                    .collect()
            };
            assert_eq!(set("roots"), [text(&src), text(&bs)].into_iter().collect());
            assert_eq!(
                set("raw_paths"),
                [text(&src), text(&bs)].into_iter().collect()
            );
            assert_eq!(
                set("paths"),
                [text(&src), text(&bs), text(&g)].into_iter().collect()
            );
        } else {
            assert!(!env.contains_key("BUSBAR_ARCHITECTURE_POLICY_SOURCES"));
            let roots =
                loads(&fs::read_to_string(&env["BUSBAR_ARCHITECTURE_SOURCES"]).unwrap()).unwrap();
            assert_eq!(json::dumps(&roots, false), format!(r#"["{}"]"#, text(&src)));
        }
        Ok(done(0, "", ""))
    });
    let log = Log(Some(Default::default()));
    let result = {
        let mut ctx = Ctx {
            engine: Some(&mut fake),
            evidence: None,
            log: &log,
            ci_host: None,
        };
        sources::check_sources(
            &mut ctx, &policy, repository, &checkout, &metadata, &trusted, &scratch,
        )
    };
    drop(fake);
    if failure.is_some() {
        assert_eq!(*scanned.borrow(), 0);
        return result;
    }
    let result = result?;
    assert_eq!(
        result.at("core_source_files").as_u64(),
        Some(if is_core { 3 } else { 0 })
    );
    assert_eq!(result.at("trusted_source_check").as_bool(), Some(true));
    assert_eq!(*scanned.borrow(), 1);
    let rows = progress_rows(&log);
    let events: Vec<&str> = rows
        .iter()
        .map(|r| r.at("event").as_str().unwrap())
        .collect();
    assert_eq!(events, ["start", "finish"]);
    let jobs = if is_core {
        Value::int(expected_jobs)
    } else {
        Value::Null
    };
    assert!(rows.iter().all(|r| py::eq(r.at("build_jobs"), &jobs)));
    Ok(result)
}

#[test]
fn core_check_materializes_generated_sources_and_retains_actual_target_inventory() {
    materialization(None, CORE, 4, 6, 4).unwrap();
}

#[test]
fn core_check_jobs_respect_cpu_and_memory_boundaries() {
    for (cpus, memory, expected) in [(2, 6, 2), (16, 6, 4), (4, 3, 1)] {
        materialization(None, CORE, cpus, memory, expected).unwrap();
    }
}

#[test]
fn plugin_source_materialization_still_builds_shipping_probe() {
    materialization(None, "GetBusbar/busbar-auth-fixture", 4, 6, 4).unwrap();
}

#[test]
fn generated_output_outside_candidate_is_still_rejected() {
    let error = materialization(Some("escaping-output"), CORE, 4, 6, 4).unwrap_err();
    assert!(error.contains("escapes its build output"));
}

#[test]
fn indirect_generated_source_is_still_rejected() {
    let error = materialization(Some("symlink-source"), CORE, 4, 6, 4).unwrap_err();
    assert!(error.contains("indirect generated source"));
}

#[test]
fn failed_check_cannot_produce_passing_source_receipt() {
    let error = materialization(Some("compiler-failure"), CORE, 4, 6, 4).unwrap_err();
    assert!(error.contains("returned non-zero exit status 1"));
}

#[test]
fn architecture_compiler_calls_have_no_host_fallback() {
    let dir = temp();
    let mut fake = Fake::new(&dir.0, 4, 6);
    fake.run = Box::new(|_| Err("unavailable".into()));
    let log = Log::default();
    let mut ctx = Ctx {
        engine: Some(&mut fake),
        evidence: None,
        log: &log,
        ci_host: None,
    };
    assert_eq!(
        ctx.run(Call::new(&s(&["cargo", "check"]))).unwrap_err(),
        "unavailable"
    );
}

// ---- test_generated_architecture_context -------------------------------------------------

struct Generated {
    fixture: Fixture,
    engine: Execution,
    subject: PathBuf,
}

impl Generated {
    fn new() -> Generated {
        let fixture = Fixture::new();
        let mut engine = fixture.execution(crate::confine::Hooks::default());
        let subject = fixture
            .roots
            .candidate
            .join("generated/open-source/busbar-auth-boundary-example");
        write(&subject.join("Cargo.toml"), "[workspace]\n");
        fs::write(subject.join("source.rs"), "pub fn example() {}\n").unwrap();
        engine.extra_readonly.push(subject.clone());
        Generated {
            fixture,
            engine,
            subject,
        }
    }

    fn args(&self) -> Args {
        Args {
            policy: PathBuf::new(),
            repository: String::new(),
            checkout: self.subject.clone(),
            scratch: self.fixture.roots.harness.join("generated-guard"),
            output: self.fixture.control.join("evidence.json"),
            trusted: self.fixture.roots.trusted.clone(),
            sdk: None,
            execution_context: None,
            execution_context_sha256: None,
            dependency_units: None,
        }
    }

    /// `native_plugins.generated_architecture_context`.
    fn context(&self) -> (PathBuf, String, Value) {
        let context = Value::Object(vec![
            (
                "architecture_checkout".into(),
                Value::Object(vec![
                    ("path".into(), Value::str(text(&self.subject))),
                    (
                        "source".into(),
                        Value::str(generated_revision(&self.subject).unwrap()),
                    ),
                ]),
            ),
            ("configuration".into(), self.fixture.config.clone()),
            ("conformance_inputs_manifest".into(), Value::Null),
            ("conformance_mounts".into(), Value::Array(vec![])),
            ("control".into(), Value::str(text(&self.fixture.control))),
            ("dependency_seed".into(), Value::Null),
            ("dependency_seed_sha256".into(), Value::Null),
            (
                "extra_readonly".into(),
                Value::Array(vec![Value::str(text(&self.subject))]),
            ),
            ("roots".into(), self.fixture.roots_value()),
        ]);
        let path = self
            .fixture
            .control
            .join("generated-open-source-auth-execution-context.json");
        fs::write(&path, json::dumps(&context, true) + "\n").unwrap();
        let digest = crate::confine::digest(&path).unwrap();
        (path, digest, context)
    }
}

#[test]
fn registered_child_preserves_roots_config_and_readonly_mount() {
    let g = Generated::new();
    let (path, expected, mut context) = g.context();
    let execution =
        Execution::from_context(&path, &expected, crate::confine::Hooks::default()).unwrap();
    assert_eq!(execution.roots, g.engine.roots);
    assert!(execution.extra_readonly.contains(&g.subject));
    let revision = generated_revision(&g.subject).unwrap();
    assert_eq!(
        validate_execution_paths(&g.args(), &execution, &context).unwrap(),
        Some(revision.clone())
    );
    assert_eq!(source_revision(&g.subject).unwrap(), revision);
    // A forged child file cannot pass the independently supplied context digest.
    context.get_mut("architecture_checkout").unwrap().set(
        "source",
        Value::str(format!("generated-sha256:{}", "0".repeat(64))),
    );
    fs::write(&path, json::dumps(&context, false)).unwrap();
    assert!(Execution::from_context(&path, &expected, crate::confine::Hooks::default()).is_err());
}

#[test]
fn unregistered_descendant_and_mismatched_subject_are_refused() {
    let g = Generated::new();
    let (path, expected, mut context) = g.context();
    let execution =
        Execution::from_context(&path, &expected, crate::confine::Hooks::default()).unwrap();
    assert!(validate_execution_paths(&g.args(), &execution, &parse("{}")).is_err());
    let child = g.subject.join("nested");
    fs::create_dir(&child).unwrap();
    for changed in [
        &g.fixture.roots.checkout,
        &child,
        &g.fixture.roots.candidate,
    ] {
        context.set(
            "architecture_checkout",
            Value::Object(vec![
                ("path".into(), Value::str(text(changed))),
                (
                    "source".into(),
                    Value::str(generated_revision(&child).unwrap()),
                ),
            ]),
        );
        assert!(validate_execution_paths(&g.args(), &execution, &context).is_err());
    }
}

#[test]
fn modified_indirect_or_git_control_source_is_refused() {
    let g = Generated::new();
    let (path, expected, context) = g.context();
    let execution =
        Execution::from_context(&path, &expected, crate::confine::Hooks::default()).unwrap();
    let source = g.subject.join("source.rs");
    fs::write(&source, "changed").unwrap();
    assert!(validate_execution_paths(&g.args(), &execution, &context).is_err());
    fs::remove_file(&source).unwrap();
    std::os::unix::fs::symlink(g.subject.join("Cargo.toml"), &source).unwrap();
    assert!(generated_revision(&g.subject).is_err());
    fs::remove_file(&source).unwrap();
    fs::create_dir(g.subject.join(".git")).unwrap();
    assert!(generated_revision(&g.subject).is_err());
}

#[test]
fn original_trusted_scratch_and_output_boundaries_still_apply() {
    let g = Generated::new();
    let (path, expected, context) = g.context();
    let execution =
        Execution::from_context(&path, &expected, crate::confine::Hooks::default()).unwrap();
    for (field, value) in [
        ("trusted", g.subject.clone()),
        ("scratch", g.subject.clone()),
        ("output", g.subject.join("result.json")),
        ("output", g.fixture.base.join("outside.json")),
    ] {
        let mut args = g.args();
        match field {
            "trusted" => args.trusted = value,
            "scratch" => args.scratch = value,
            _ => args.output = value,
        }
        assert!(validate_execution_paths(&args, &execution, &context).is_err());
    }
}

#[test]
fn ambiguous_raw_concatenation_trees_and_permissions_have_distinct_fingerprints() {
    let g = Generated::new();
    let (first, second) = (g.fixture.base.join("first"), g.fixture.base.join("second"));
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::write(first.join("a"), b"x").unwrap();
    fs::write(first.join("b"), b"y").unwrap();
    fs::write(second.join("a"), b"xb\0y").unwrap();
    assert_ne!(
        generated_revision(&first).unwrap(),
        generated_revision(&second).unwrap()
    );
    let before = generated_revision(&first).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(first.join("a"), fs::Permissions::from_mode(0o700)).unwrap();
    assert_ne!(generated_revision(&first).unwrap(), before);
}

#[test]
fn generated_fingerprint_matches_the_python_encoding() {
    // sha256 of json.dumps(sorted rows, sort_keys=True, separators=(',', ':')).
    let g = Generated::new();
    let root = g.fixture.base.join("tree");
    write(&root.join("d/f"), "x");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(root.join("d/f"), fs::Permissions::from_mode(0o644)).unwrap();
    let rows = format!(
        r#"[{{"kind":"directory","path":"d","permissions":493,"sha256":null,"size":0}},{{"kind":"file","path":"d/f","permissions":420,"sha256":"{}","size":1}}]"#,
        crate::sha256::hex(b"x")
    );
    assert_eq!(
        generated_revision(&root).unwrap(),
        format!("generated-sha256:{}", crate::sha256::hex(rows.as_bytes()))
    );
}

#[test]
fn main_rejects_mutation_after_confined_checks() {
    let g = Generated::new();
    let policy = g.fixture.roots.trusted.join("policy.toml");
    fs::write(&policy, "version=1\n").unwrap();
    let mut args = g.args();
    args.policy = policy;
    args.repository = "GetBusbar/example".into();
    let revision = generated_revision(&g.subject).unwrap();
    let receipt = finish(
        &args,
        Value::Object(vec![]),
        Some(&g.engine),
        Some(revision.clone()),
    )
    .unwrap();
    assert_eq!(receipt.at("source").as_str(), Some(revision.as_str()));
    assert_eq!(receipt.at("release_eligible").as_bool(), Some(false));
    fs::write(
        g.subject.join("source.rs"),
        "mutated during child execution",
    )
    .unwrap();
    let error = finish(
        &args,
        Value::Object(vec![]),
        Some(&g.engine),
        Some(revision),
    )
    .unwrap_err();
    assert!(error.contains("changed during qualification"));
}

// ---- test_c_witness --------------------------------------------------------------------

struct CRecipe {
    dir: TempDir,
    recipe: Value,
    entry: Value,
    policy: Policy,
    revision: String,
}

const C_REPOSITORY: &str = "GetBusbar/busbar-fixture-c";

impl CRecipe {
    fn new() -> CRecipe {
        let dir = temp();
        let recipe = parse(
            r#"{"sources": ["owner/plugin.c"], "test-root": "owner",
            "unit": {"sources": ["owner/tests/unit.c"], "defines": ["BUSBAR_FIXTURE_UNIT"]},
            "schema": {"source": "owner/tests/schema.c", "driver": "owner/tests/schema.py"}}"#,
        );
        let entry = parse(
            r#"{"language": "c", "private": false, "kind": "secret", "sources": ["owner/plugin.c"]}"#,
        );
        let mut data = parse(r#"{"repositories": {}}"#);
        data.get_mut("repositories")
            .unwrap()
            .set(C_REPOSITORY, entry.clone());
        for path in [
            "owner/plugin.c",
            "owner/tests/unit.c",
            "owner/tests/schema.c",
            "owner/tests/schema.py",
        ] {
            write(
                &dir.0.join(path),
                if path.ends_with(".c") {
                    "/* fixture */\n"
                } else {
                    "# fixture\n"
                },
            );
        }
        write(
            &dir.0.join("testing/c-witness.json"),
            &json::dumps(&recipe, false),
        );
        let mut fixture = CRecipe {
            dir,
            recipe,
            entry,
            policy: bare(data),
            revision: String::new(),
        };
        fixture.git(&["init", "-q"]);
        fixture.commit();
        fixture
    }

    fn git(&self, args: &[&str]) -> String {
        let mut argv = s(&[
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-C",
            &text(&self.dir.0),
        ]);
        argv.extend(s(args));
        let output = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn commit(&mut self) {
        self.git(&["add", "."]);
        self.git(&["commit", "-qm", "C owner fixture"]);
        self.revision = self.git(&["rev-parse", "HEAD"]);
    }

    fn load(&self) -> Result<Value> {
        sources::load_c_recipe(
            &self.policy,
            C_REPOSITORY,
            &self.dir.0,
            Some(&self.revision),
        )
    }
}

#[test]
fn exact_owner_recipe_preserves_required_data() {
    let f = CRecipe::new();
    assert!(py::eq(&f.load().unwrap(), &f.recipe));
}

#[test]
fn missing_unknown_or_command_fields_and_invalid_paths_refuse() {
    let f = CRecipe::new();
    let mut bad = Vec::new();
    for key in f.recipe.keys() {
        let mut value = f.recipe.clone();
        if let Value::Object(rows) = &mut value {
            rows.retain(|(k, _)| k != key);
        }
        bad.push(value);
    }
    let mut value = f.recipe.clone();
    value.set("command", parse(r#"["sh", "-c", "true"]"#));
    bad.push(value);
    let mut value = f.recipe.clone();
    value.set("test-root", "../outside".into());
    bad.push(value);
    for field in ["source", "driver"] {
        let mut value = f.recipe.clone();
        value
            .get_mut("schema")
            .unwrap()
            .set(field, "/outside".into());
        bad.push(value);
    }
    for define in ["-include/private", "BUSBAR_X=1", "BUSBAR_X -o elsewhere"] {
        let mut value = f.recipe.clone();
        value
            .get_mut("unit")
            .unwrap()
            .set("defines", Value::Array(vec![define.into()]));
        bad.push(value);
    }
    let mut value = f.recipe.clone();
    value.set("sources", parse(r#"["owner/other.c"]"#));
    bad.push(value);
    for value in bad {
        assert!(
            crate::product::validate_c_recipe(&value, &f.entry).is_err(),
            "{}",
            json::dumps(&value, false)
        );
    }
}

#[test]
fn modified_recipe_source_and_wrong_pin_refuse() {
    let f = CRecipe::new();
    let metadata = f.dir.0.join("testing/c-witness.json");
    let mut changed = f.recipe.clone();
    changed.set("command", "true".into());
    fs::write(&metadata, json::dumps(&changed, false)).unwrap();
    assert!(f.load().unwrap_err().contains("committed bytes"));
    fs::write(&metadata, json::dumps(&f.recipe, false)).unwrap();
    fs::write(f.dir.0.join("owner/plugin.c"), "changed").unwrap();
    assert!(f.load().unwrap_err().contains("committed bytes"));
    let error = sources::load_c_recipe(&f.policy, C_REPOSITORY, &f.dir.0, Some(&"0".repeat(40)))
        .unwrap_err();
    assert!(error.contains("admitted commit"));
}

#[test]
fn source_and_directory_symlinks_refuse() {
    let mut f = CRecipe::new();
    let source = f.dir.0.join("owner/plugin.c");
    fs::remove_file(&source).unwrap();
    std::os::unix::fs::symlink("tests/unit.c", &source).unwrap();
    f.commit();
    assert!(f.load().unwrap_err().contains("regular Git blob"));
}

#[test]
fn source_root_directory_symlink_refuses() {
    let f = CRecipe::new();
    fs::rename(f.dir.0.join("owner"), f.dir.0.join("elsewhere")).unwrap();
    std::os::unix::fs::symlink("elsewhere", f.dir.0.join("owner")).unwrap();
    assert!(f.load().unwrap_err().contains("indirect product input"));
}

#[test]
fn duplicate_recipe_keys_refuse() {
    assert!(crate::product::loads_unique(br#"{"a": 1, "b": {"c": 1, "c": 2}}"#).is_err());
    assert!(crate::product::loads_unique(br#"{"a": [{"x": 1}, {"x": 2}], "b": "a\"b"}"#).is_ok());
}

#[test]
fn vector_cannot_override_header_or_add_commands() {
    let f = CRecipe::new();
    let mut data = f.policy.data.clone();
    data.set("version", Value::int(1));
    data.set("core", parse("{}"));
    data.set("assembly", parse(r#"{"package": "busbar-default"}"#));
    let policy = Policy::new(data).unwrap();
    let a = "a".repeat(40);
    let vector = parse(&format!(
        r#"{{"sdk": "{a}", "products": [], "c_witness": {{"repo": "busbar-fixture-c",
        "url": "https://github.com/{C_REPOSITORY}", "commit": "{}", "sdk": "{a}", "kind": "secret",
        "language": "c", "header": "{PUBLIC_C_HEADER}"}}}}"#,
        f.revision
    ));
    graph::vector_revisions(&policy, &vector).unwrap();
    for (key, value) in [
        ("header", "../private.h"),
        ("command", "true"),
        ("kind", "store"),
        ("language", "rust"),
    ] {
        let mut changed = vector.clone();
        changed.get_mut("c_witness").unwrap().set(key, value.into());
        assert!(graph::vector_revisions(&policy, &changed).is_err(), "{key}");
    }
}

#[test]
fn c_includes_match_the_multiline_pattern() {
    assert_eq!(
        sources::includes("#include \"busbar_plugin.h\"\nint x;\n"),
        ["\"busbar_plugin.h\""]
    );
    assert_eq!(
        sources::includes("  #  include <stdio.h>\n#include \"busbar_plugin.h\"\n"),
        ["<stdio.h>", "\"busbar_plugin.h\""]
    );
    assert_eq!(
        sources::includes("int x; #include <a.h>\n"),
        Vec::<String>::new()
    );
    assert!(crate::product::relative_path(&Value::str("owner/a.c")).is_ok());
    assert!(crate::product::relative_path(&Value::str("../a.c")).is_err());
}

#[test]
fn witness_doc_extraction_matches_the_python_patterns() {
    use witness::{code_blocks, doc_text, error_codes, has_main};
    let source = "  /// ```compile_fail,E0277\n  /// # use x;\n  /// let a = 1;\n  /// ```\n//! ```\n//!fn main() {}\n//! ```\n// not docs\n";
    let docs = doc_text(source);
    assert_eq!(
        docs,
        "```compile_fail,E0277\n# use x;\nlet a = 1;\n```\n```\nfn main() {}\n```"
    );
    let blocks = code_blocks(&docs);
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].0, "compile_fail,E0277");
    assert_eq!(blocks[1].1, "fn main() {}\n");
    assert_eq!(
        error_codes("compile_fail,E0277,E06031"),
        s(&["E0277", "E0603"])
    );
    assert!(
        has_main("pub fn main () {}") && !has_main("fn mainly() {}") && !has_main("xfn main() {}")
    );
}

#[test]
fn python_text_helpers() {
    assert_eq!(splitlines("a\r\nb\rc\n\nd"), ["a", "b", "c", "", "d"]);
    assert_eq!(split_ws(" a\tb \u{1c}c "), ["a", "b", "c"]);
}
