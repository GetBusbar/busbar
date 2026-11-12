//! Trusted dependency units can only skip work: any doubt builds from scratch.
use super::*;
use crate::confine::{Execution, Roots};
use std::collections::BTreeSet;

const REPO: &str = "GetBusbar/busbar-transport-example";
const PIPELINE: i64 = 77;

fn env() -> Dict {
    let mut env = Dict::default();
    for (k, v) in [
        ("RUSTUP_TOOLCHAIN", "1.98.0"),
        ("CARGO_PROFILE_DEV_DEBUG", "0"),
        ("CARGO_PROFILE_TEST_DEBUG", "0"),
        ("RUSTC_WRAPPER", ""),
        ("RUSTC_WORKSPACE_WRAPPER", ""),
    ] {
        env.set(k, v);
    }
    env
}

#[test]
fn identity_key_is_byte_compatible_with_the_python_controller() {
    // native_dep_cache.key(identity(...)) for the same inputs (Python 3.15).
    let identity = identity(
        "GetBusbar/busbar-transport-grpc",
        &"ab".repeat(32),
        &format!("sha256:{}", "cd".repeat(32)),
        &env(),
        "busbar-transport-grpc-plugin",
    );
    assert_eq!(
        identity.at("commands_sha256").as_str(),
        Some("9bfbe011a40f928533c3bdc3170c17c79fb601d7f4455ef65cf179ef548ed4e9")
    );
    assert_eq!(
        key(&identity),
        "894c85eb320cca5dac99c5120299c8a20101b8f4e0fc30f7a2ad993d4ca7196d"
    );
}

#[test]
fn identity_covers_lock_image_environment_and_cargo_home() {
    let base = identity(REPO, &"0".repeat(64), "sha256:a", &env(), "w");
    let mut flags = env();
    flags.set("RUSTFLAGS", "-Cfoo");
    let variants = [
        identity(REPO, &"1".repeat(64), "sha256:a", &env(), "w"),
        identity(REPO, &"0".repeat(64), "sha256:b", &env(), "w"),
        identity(REPO, &"0".repeat(64), "sha256:a", &flags, "w"),
        identity(REPO, &"0".repeat(64), "sha256:a", &env(), "other"),
    ];
    let keys: BTreeSet<String> = variants.iter().chain([&base]).map(key).collect();
    assert_eq!(keys.len(), 5);
    assert_eq!(
        base.at("cargo_home").as_str(),
        Some(confine::INVOCATION_CARGO_HOME)
    );
}

struct Fixture {
    base: PathBuf,
    q: Q,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        discard(Some(&self.base));
    }
}

fn fixture() -> Fixture {
    let base = sp::resolve(&std::env::temp_dir()).join(format!("depcache-{}", sp::uuid_hex()));
    let control = base.join("boundary-1-2");
    let roots = Roots {
        checkout: base.join("checkout"),
        candidate: control.join("candidate"),
        trusted: base.join("trusted"),
        harness: control.join("harness"),
    };
    for path in [
        &roots.checkout,
        &roots.candidate,
        &roots.trusted,
        &roots.harness,
    ] {
        std::fs::create_dir_all(path).unwrap();
    }
    std::fs::write(roots.checkout.join("Cargo.lock"), "version = 4\n").unwrap();
    let evidence = control.join("evidence");
    std::fs::create_dir(&evidence).unwrap();
    let config = json::parse(
        format!(
            r#"{{"schema": "busbar.native-confinement/2", "docker": "/bin/echo",
            "docker_sha256": "{}", "docker_host": "unix:///var/run/docker.sock",
            "image": "sha256:{}", "runtime": "runc", "uid": 1000, "gid": 1000,
            "{}": "/usr/local/bin/interpreter", "environment": {{"PATH": "/usr/bin:/bin"}},
            "resources": {{"cpus": 2, "memory_bytes": 2147483648, "pids": 256}},
            "collector": {{"docker_host": "unix:///var/run/docker.sock", "uid": 525288, "gid": 525288}},
            "isolation": {{"storage_kind": "tmpfs", "storage_reserve_bytes": 0,
              "storage_root": "{}", "storage_bytes": 67108864, "storage_inodes": 4096,
              "uid_map": [0, 524288, 65536], "gid_map": [0, 524288, 65536]}}}}"#,
            sha256::file(Path::new("/bin/echo")).unwrap(),
            "a".repeat(64),
            crate::native::pysteps::INTERPRETER_KEY,
            sp::text(&base)
        )
        .as_bytes(),
    )
    .unwrap();
    let execution = Execution::new(
        config,
        roots.clone(),
        &control,
        roots.trusted.join("entry.py"),
    )
    .unwrap();
    let policy = json::parse(
        format!(
            r#"{{"repositories": {{"{REPO}": {{"packages": [
            {{"name": "busbar-transport-example", "role": "implementation"}},
            {{"name": "busbar-transport-example-plugin", "role": "wrapper"}}]}}}}}}"#
        )
        .as_bytes(),
    )
    .unwrap();
    let mut q_env = env();
    q_env.set(
        "CARGO_TARGET_DIR",
        sp::text(&roots.candidate.join("target")),
    );
    let q = Q {
        conformance_only: false,
        external_conformance: false,
        evaluation_only: false,
        root: roots.checkout.clone(),
        trusted: roots.trusted.clone(),
        work: roots.candidate.clone(),
        control,
        harness: roots.harness.clone(),
        evidence,
        execution: Some(execution),
        repository: REPO.into(),
        policy,
        receipt: object([("steps", Value::Array(Vec::new()))]),
        env: q_env,
        staged_fixtures: Vec::new(),
        host: None,
        sdk_checkout: None,
        containers: Vec::new(),
    };
    Fixture { base, q }
}

fn write_target(root: &Path) {
    for (relative, data) in [
        ("deps/libserde-0123456789abcdef.rlib", "serde"),
        ("deps/libserde-0123456789abcdef.rmeta", "serde-meta"),
        ("deps/serde-0123456789abcdef.d", "dep-info"),
        (".fingerprint/serde-0123456789abcdef/lib-serde", "fp"),
        (
            "build/ring-fedcba9876543210/output",
            "cargo:rustc-link-lib=ring",
        ),
        (
            "deps/libbusbar_transport_example-1111111111111111.rlib",
            "member",
        ),
        (
            "deps/libbusbar_transport_example_plugin.so",
            "member-cdylib",
        ),
        (
            ".fingerprint/busbar-transport-example-1111111111111111/lib",
            "member-fp",
        ),
        (
            "build/busbar-transport-example-2222222222222222/output",
            "member-build",
        ),
        (
            "libbusbar_transport_example_plugin.so",
            "profile-root output",
        ),
        ("incremental/busbar_transport_example-x/s", "incremental"),
        ("examples/demo", "example"),
    ] {
        let path = root.join("debug").join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, data).unwrap();
    }
    std::fs::write(root.join(".rustc_info.json"), "{}").unwrap();
}

fn members() -> Vec<String> {
    vec![
        "busbar-transport-example".into(),
        "busbar-transport-example-plugin".into(),
    ]
}

struct Fake {
    files: BTreeMap<(String, String), Vec<u8>>,
    package_files: Value,
    packages: Value,
    downloads: usize,
}

impl Default for Fake {
    fn default() -> Self {
        Fake {
            files: BTreeMap::new(),
            package_files: Value::Null,
            packages: Value::Null,
            downloads: 0,
        }
    }
}

impl Registry for Fake {
    fn read(
        &mut self,
        version: &str,
        name: &str,
        _limit: u64,
    ) -> Result<Option<Vec<u8>>, Fallback> {
        Ok(self.files.get(&(version.into(), name.into())).cloned())
    }
    fn json(&mut self, path: &str) -> Result<Value, Fallback> {
        Ok(if path.starts_with("/packages?") {
            self.packages.clone()
        } else {
            self.package_files.clone()
        })
    }
    fn download(
        &mut self,
        version: &str,
        name: &str,
        destination: &Path,
        size: u64,
        sha: &str,
    ) -> Result<(), Fallback> {
        self.downloads += 1;
        let data = self.files[&(version.to_owned(), name.to_owned())].clone();
        std::fs::write(destination, &data).unwrap();
        need(
            data.len() as u64 == size && sha256::hex(&data) == sha,
            "downloaded package differs from its protected pin",
        )
    }
    fn upload(&mut self, _: &str, _: &str, _: &Path) -> Result<(), Fallback> {
        unavailable("consumers never upload")
    }
}

struct Publish {
    tamper: bool,
    identity: Option<Value>,
    pipeline: i64,
    reference: &'static str,
    duplicate: bool,
    file_digest: Option<String>,
}

impl Default for Publish {
    fn default() -> Self {
        Publish {
            tamper: false,
            identity: None,
            pipeline: PIPELINE,
            reference: "dev",
            duplicate: false,
            file_digest: None,
        }
    }
}

fn published(f: &mut Fixture, options: Publish) -> (Fake, String) {
    let work = f.base.join(format!("producer-{}", sp::uuid_hex()));
    std::fs::create_dir(&work).unwrap();
    let target = work.join("target");
    write_target(&target);
    strip_path_units(&target, &members()).unwrap();
    let archive = work.join("units.tar.gz");
    let mut files = pack(&target, &archive).unwrap();
    if let Some(digest) = &options.file_digest {
        *files
            .get_mut("debug/deps/libserde-0123456789abcdef.rlib")
            .unwrap() = digest.clone();
    }
    let mut data = std::fs::read(&archive).unwrap();
    let digest = sha256::hex(&data);
    let name = format!("units-{digest}.tar.gz");
    let image =
        f.q.execution()
            .config
            .at("image")
            .as_str()
            .unwrap()
            .to_owned();
    let lock = sha256::file(&f.q.root.join("Cargo.lock")).unwrap();
    let wanted = identity(
        REPO,
        &lock,
        &image,
        &f.q.env,
        "busbar-transport-example-plugin",
    );
    let version = key(&wanted);
    let manifest = object([
        ("schema", SCHEMA.into()),
        ("key", version.as_str().into()),
        ("identity", options.identity.unwrap_or(wanted)),
        (
            "archive",
            object([
                ("name", name.as_str().into()),
                ("sha256", digest.as_str().into()),
                ("bytes", (data.len() as u64).into()),
            ]),
        ),
        (
            "files",
            Value::Object(
                files
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().into()))
                    .collect(),
            ),
        ),
        ("product", object([("commit", "d".repeat(40).into())])),
        (
            "producer",
            object([
                ("pipeline_id", Value::int(PIPELINE)),
                ("commit", "c".repeat(40).into()),
            ]),
        ),
    ]);
    let pipelines = Value::Array(vec![object([
        ("id", Value::int(options.pipeline)),
        ("ref", options.reference.into()),
        ("sha", "c".repeat(40).into()),
        ("source", "push".into()),
    ])]);
    let mut rows = vec![
        object([
            ("file_name", MANIFEST.into()),
            ("pipelines", pipelines.clone()),
        ]),
        object([
            ("file_name", name.as_str().into()),
            ("file_sha256", digest.as_str().into()),
            ("pipelines", pipelines),
        ]),
    ];
    if options.duplicate {
        rows.push(rows[1].clone());
    }
    if options.tamper {
        let last = data.len() - 1;
        data[last] ^= 1;
    }
    let mut fake = Fake {
        package_files: Value::Array(rows),
        packages: Value::Array(vec![object([
            ("id", Value::int(9)),
            ("name", PACKAGE.into()),
            ("version", version.as_str().into()),
        ])]),
        ..Default::default()
    };
    fake.files
        .insert((version.clone(), MANIFEST.into()), json::encoded(&manifest));
    fake.files.insert((version.clone(), name), data);
    (fake, version)
}

fn record(f: &Fixture) -> Value {
    f.q.receipt.at("dependency_units").clone()
}

#[test]
fn hit_restores_a_verified_sealed_seed_outside_every_candidate_mount() {
    let mut f = fixture();
    let (mut fake, version) = published(&mut f, Publish::default());
    let seed = restore(&mut f.q, Some(&mut fake)).unwrap().expect("hit");
    let r = record(&f);
    assert_eq!(
        r.at("status").as_str(),
        Some("hit"),
        "{}",
        json::dumps(&r, true)
    );
    assert_eq!(r.at("key").as_str(), Some(version.as_str()));
    assert_eq!(seed, sp::resolve(&f.q.control.join("dependency-units")));
    let roots = f.q.execution().roots.clone();
    for root in [
        &roots.candidate,
        &roots.checkout,
        &roots.harness,
        &roots.trusted,
    ] {
        assert!(!seed.starts_with(sp::resolve(root)));
    }
    assert!(
        seed.join("debug/deps/libserde-0123456789abcdef.rlib")
            .is_file()
    );
    let names: Vec<String> = sp::rglob(&seed).iter().map(|p| sp::text(p)).collect();
    assert!(names.iter().all(
        |n| !n.contains("busbar_transport_example") && !n.contains("busbar-transport-example")
    ));
    assert_eq!(
        std::fs::metadata(&seed).unwrap().permissions().mode() & 0o222,
        0
    );
    install_job_target(&mut f.q, Some(&seed)).unwrap();
    let target = PathBuf::from(f.q.env.get("CARGO_TARGET_DIR").unwrap());
    assert_eq!(
        std::fs::read(target.join("debug/deps/libserde-0123456789abcdef.rlib")).unwrap(),
        b"serde"
    );
    assert!(!f.q.control.join("dependency-units.tar.gz").exists());
}

#[test]
fn miss_builds_from_scratch() {
    let mut f = fixture();
    let mut fake = Fake::default();
    assert!(restore(&mut f.q, Some(&mut fake)).unwrap().is_none());
    assert_eq!(record(&f).at("status").as_str(), Some("miss"));
    install_job_target(&mut f.q, None).unwrap();
    assert!(!PathBuf::from(f.q.env.get("CARGO_TARGET_DIR").unwrap()).exists());
}

#[test]
fn archive_digest_mismatch_builds_from_scratch_and_leaves_nothing() {
    let mut f = fixture();
    let (mut fake, _) = published(
        &mut f,
        Publish {
            tamper: true,
            ..Default::default()
        },
    );
    assert!(restore(&mut f.q, Some(&mut fake)).unwrap().is_none());
    let r = record(&f);
    assert_eq!(r.at("status").as_str(), Some("fallback"));
    assert!(r.at("reason").as_str().unwrap().contains("differs"));
    assert!(!f.q.control.join("dependency-units").exists());
    assert!(!f.q.control.join("dependency-units.tar.gz").exists());
}

#[test]
fn file_digest_mismatch_inside_a_valid_archive_builds_from_scratch() {
    let mut f = fixture();
    let (mut fake, _) = published(
        &mut f,
        Publish {
            file_digest: Some("0".repeat(64)),
            ..Default::default()
        },
    );
    assert!(restore(&mut f.q, Some(&mut fake)).unwrap().is_none());
    assert!(
        record(&f)
            .at("reason")
            .as_str()
            .unwrap()
            .contains("inventory")
    );
    assert!(!f.q.control.join("dependency-units").exists());
}

#[test]
fn identity_mismatch_never_downloads() {
    let mut f = fixture();
    let other = identity(
        REPO,
        &"f".repeat(64),
        "sha256:b",
        &env(),
        "busbar-transport-example-plugin",
    );
    let (mut fake, _) = published(
        &mut f,
        Publish {
            identity: Some(other),
            ..Default::default()
        },
    );
    assert!(restore(&mut f.q, Some(&mut fake)).unwrap().is_none());
    assert!(
        record(&f)
            .at("reason")
            .as_str()
            .unwrap()
            .contains("identity")
    );
    assert_eq!(fake.downloads, 0);
}

#[test]
fn uploads_outside_the_producer_pipeline_or_duplicated_are_rejected() {
    for options in [
        Publish {
            pipeline: 78,
            ..Default::default()
        },
        Publish {
            reference: "feature",
            ..Default::default()
        },
        Publish {
            duplicate: true,
            ..Default::default()
        },
    ] {
        let mut f = fixture();
        let (mut fake, _) = published(&mut f, options);
        assert!(restore(&mut f.q, Some(&mut fake)).unwrap().is_none());
        assert_eq!(record(&f).at("status").as_str(), Some("fallback"));
        assert_eq!(fake.downloads, 0);
    }
}

#[test]
fn candidate_copy_cannot_write_the_seed() {
    let mut f = fixture();
    let (mut fake, _) = published(&mut f, Publish::default());
    let seed = restore(&mut f.q, Some(&mut fake)).unwrap().unwrap();
    let before = inventory(&seed).unwrap();
    let copy = f.q.execution().roots.candidate.join("probe-target");
    install(&seed, &copy, None).unwrap();
    std::fs::write(
        copy.join("debug/deps/libserde-0123456789abcdef.rlib"),
        "candidate poison",
    )
    .unwrap();
    std::fs::write(copy.join("debug/deps/new"), "added").unwrap();
    assert_eq!(inventory(&seed).unwrap(), before);
    assert!(std::fs::write(seed.join("debug/deps/libserde-0123456789abcdef.rlib"), "x").is_err());
    assert!(
        install(&seed, &copy, None).is_err(),
        "an existing destination is refused"
    );
}

#[test]
fn seed_inside_a_candidate_mounted_root_is_refused() {
    let mut f = fixture();
    let roots = f.q.execution().roots.clone();
    for root in [
        &roots.candidate,
        &roots.checkout,
        &roots.harness,
        &roots.trusted,
    ] {
        let inside = root.join("units");
        std::fs::create_dir(&inside).unwrap();
        assert!(
            readonly_seed(&inside, &roots)
                .unwrap_err()
                .contains("candidate-mounted root")
        );
    }
}

#[test]
fn installed_copy_has_one_timestamp() {
    let f = fixture();
    let target = f.base.join("t");
    write_target(&target);
    let stamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000_000);
    install(&target, &f.base.join("copy"), Some(stamp)).unwrap();
    let stamps: BTreeSet<SystemTime> = sp::rglob(&f.base.join("copy"))
        .iter()
        .filter(|p| p.is_file())
        .map(|p| std::fs::metadata(p).unwrap().modified().unwrap())
        .collect();
    assert_eq!(stamps, BTreeSet::from([stamp]));
}

#[test]
fn strip_keeps_only_registry_and_git_units() {
    let f = fixture();
    let target = f.base.join("t");
    write_target(&target);
    strip_path_units(&target, &members()).unwrap();
    assert_eq!(
        inventory(&target)
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        [
            "debug/.fingerprint/serde-0123456789abcdef/lib-serde",
            "debug/build/ring-fedcba9876543210/output",
            "debug/deps/libserde-0123456789abcdef.rlib",
            "debug/deps/libserde-0123456789abcdef.rmeta",
            "debug/deps/serde-0123456789abcdef.d",
        ]
    );
}

#[test]
fn pack_is_deterministic_and_round_trips_long_names() {
    let f = fixture();
    let target = f.base.join("t");
    write_target(&target);
    let long = format!(
        "debug/build/{}-0123456789abcdef/out/file.rs",
        "x".repeat(120)
    );
    std::fs::create_dir_all(target.join(&long).parent().unwrap()).unwrap();
    std::fs::write(target.join(&long), "long").unwrap();
    let files = pack(&target, &f.base.join("a.tar.gz")).unwrap();
    pack(&target, &f.base.join("b.tar.gz")).unwrap();
    assert_eq!(
        std::fs::read(f.base.join("a.tar.gz")).unwrap(),
        std::fs::read(f.base.join("b.tar.gz")).unwrap()
    );
    unpack(&f.base.join("a.tar.gz"), &f.base.join("out"), &files).unwrap();
    assert_eq!(
        std::fs::read(f.base.join("out").join(&long)).unwrap(),
        b"long"
    );
}

#[test]
fn unpack_rejects_escaping_linked_and_unlisted_entries() {
    let f = fixture();
    for (index, (name, kind)) in [
        ("../escape", b'0'),
        ("debug/link", b'2'),
        ("/abs", b'0'),
        ("debug/unlisted", b'0'),
    ]
    .into_iter()
    .enumerate()
    {
        let raw = f.base.join(format!("bad-{index}.tar"));
        let mut data = tar_header(name, kind, 0, 0o644);
        data.extend_from_slice(&[0u8; 1024]);
        std::fs::write(&raw, data).unwrap();
        let archive = f.base.join(format!("bad-{index}.tar.gz"));
        let status = Command::new(GZIP)
            .args(["-n", "-c"])
            .stdin(File::open(&raw).unwrap())
            .stdout(File::create(&archive).unwrap())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(
            unpack(
                &archive,
                &f.base.join(format!("out-{index}")),
                &BTreeMap::new()
            )
            .is_err(),
            "{name}"
        );
    }
}

#[test]
fn rebuilt_units_ignore_members_and_trailers() {
    let text = "   Compiling serde v1.0.0\n   Checking busbar-x v1.6.0 (/w/x)\n    Finished `dev` profile\n   Compiling busbar-contract v1.6.0 (https://github.com/GetBusbar/busbar?rev=a#a)\nCompiling top-level v1\n";
    assert_eq!(
        rebuilt_dependency_units(text, &BTreeSet::from(["busbar-x".to_owned()])),
        ["serde v1.0.0", "busbar-contract v1.6.0"]
    );
}

#[test]
fn producer_commands_are_the_plugin_steps() {
    let source = include_str!("../plugins.rs");
    for (name, argv) in plugin_commands("NAME") {
        assert!(source.contains(&format!("\"{name}\",")), "{name}");
        let flags: Vec<&String> = argv
            .iter()
            .filter(|a| a.starts_with("--") && *a != "--no-run")
            .collect();
        for flag in flags {
            assert!(source.contains(&format!("\"{flag}\"")), "{name} {flag}");
        }
    }
}

#[test]
fn stub_workspace_keeps_manifests_and_neutralises_code() {
    let f = fixture();
    let source = f.base.join("src");
    std::fs::create_dir_all(source.join("crate/src")).unwrap();
    std::fs::write(
        source.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crate\"]\n",
    )
    .unwrap();
    std::fs::write(source.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        source.join("crate/Cargo.toml"),
        "[package]\nname = \"crate\"\n",
    )
    .unwrap();
    std::fs::write(
        source.join("crate/build.rs"),
        "fn main() { std::process::exit(1) }",
    )
    .unwrap();
    std::fs::write(
        source.join("crate/src/lib.rs"),
        "compile_error!(\"candidate\");",
    )
    .unwrap();
    std::fs::write(source.join("crate/data.json"), "{\"secret\": 1}").unwrap();
    std::fs::create_dir(source.join(".cargo")).unwrap();
    std::fs::write(
        source.join(".cargo/config.toml"),
        "[build]\nrustflags = [\"-Cfoo\"]\n",
    )
    .unwrap();
    let stub = f.base.join("stub");
    stub_workspace(&source, &stub, None).unwrap();
    assert_eq!(
        std::fs::read_to_string(stub.join("crate/Cargo.toml")).unwrap(),
        "[package]\nname = \"crate\"\n"
    );
    assert_eq!(std::fs::read(stub.join("crate/build.rs")).unwrap(), STUB);
    assert_eq!(std::fs::read(stub.join("crate/src/lib.rs")).unwrap(), STUB);
    assert_eq!(std::fs::read(stub.join("crate/data.json")).unwrap(), b"");
    assert!(!stub.join(".cargo").exists());
}

/// Manual interop check: `DEPCACHE_INTEROP=<archive>:<files.json>` unpacks a
/// Python-packed archive with this reader.
#[test]
#[ignore]
fn python_packed_archive_unpacks() {
    let spec = std::env::var("DEPCACHE_INTEROP").unwrap();
    let (archive, files) = spec.split_once(':').unwrap();
    let parsed = json::parse(&std::fs::read(files).unwrap()).unwrap();
    let expected = parsed
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
        .collect();
    let out = std::env::temp_dir().join(format!("interop-{}", sp::uuid_hex()));
    unpack(Path::new(archive), &out, &expected).unwrap();
    discard(Some(&out));
}
