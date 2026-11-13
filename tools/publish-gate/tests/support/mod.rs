// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! A release commit plus a candidate, built fresh per case: the owner's clone (a real git repo
//! with a K2-signed version tag), the candidate as CI writes it (real unsigned plugin tarballs made
//! by busbar-plugin-pack, an OCI layout, SBOMs, the conformance fetch and its manifest), the
//! owner's trust file and keys, and a `state/` directory that answers every read-only lookup.
//!
//! K1 (the root) and the release signer are P-256 keys made with openssl; K2 is a software ssh
//! key standing in for the FIDO2 key, so only the harness may relax the hardware-type check.
#![allow(dead_code)]

use busbar_publish_gate::gate::PLUGIN_TARGETS;
use busbar_publish_gate::py::{self, dict, dumps, Dump, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const VERSION: &str = "1.6.0";
pub const PLUGIN: &str = "busbar-store-fake";
pub const PVER: &str = "1.6.0";
pub const PLUGIN_COMMIT: &str = "cccccccccccccccccccccccccccccccccccccccc";
pub const CORE: &str = "GetBusbar/busbar";
pub const MCI: &str = "https://eu-central.modernci.dev";

pub fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The busbar-plugin-pack the cases use: $PACK, or the repo's own build.
pub fn pack() -> Option<String> {
    if let Ok(p) = std::env::var("PACK") {
        if Path::new(&p).is_file() {
            return Some(p);
        }
    }
    let repo = crate_dir().join("../..");
    for prof in ["debug", "release"] {
        let p = repo.join("target").join(prof).join("busbar-plugin-pack");
        if p.is_file() {
            return Some(p.to_string_lossy().into_owned());
        }
    }
    None
}

pub fn sh(cmd: &[&str], cwd: Option<&Path>) -> Vec<u8> {
    let mut c = Command::new(cmd[0]);
    c.args(&cmd[1..]);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    let out = c.output().unwrap_or_else(|e| panic!("{}: {e}", cmd[0]));
    assert!(
        out.status.success(),
        "{:?} failed: {}",
        cmd,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

pub fn git(root: &Path, args: &[&str]) -> String {
    let mut v = vec![
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "-c",
        "tag.gpgSign=false",
        "-c",
        "commit.gpgSign=false",
    ];
    v.extend_from_slice(args);
    String::from_utf8(sh(&v, Some(root)))
        .unwrap()
        .trim()
        .to_string()
}

fn tar_bytes(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in members {
        let mut h = tar::Header::new_ustar();
        h.set_path(name).unwrap();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_cksum();
        b.append(&h, *data).unwrap();
    }
    b.into_inner().unwrap()
}

pub fn tgz(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&tar_bytes(members)).unwrap();
    e.finish().unwrap()
}

pub fn raw_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    tar_bytes(members)
}

/// A stored (uncompressed) zip, as `zipfile.ZipFile(..., "w").writestr` writes it.
pub fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in members {
        let off = out.len() as u32;
        let crc = crc32fast::hash(data);
        let n = name.as_bytes();
        let head = |sig: u32, central: bool| {
            let mut h = Vec::new();
            h.extend_from_slice(&sig.to_le_bytes());
            if central {
                h.extend_from_slice(&20u16.to_le_bytes());
            }
            h.extend_from_slice(&20u16.to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // flags
            h.extend_from_slice(&0u16.to_le_bytes()); // stored
            h.extend_from_slice(&0u16.to_le_bytes()); // time
            h.extend_from_slice(&0x21u16.to_le_bytes()); // date
            h.extend_from_slice(&crc.to_le_bytes());
            h.extend_from_slice(&(data.len() as u32).to_le_bytes());
            h.extend_from_slice(&(data.len() as u32).to_le_bytes());
            h.extend_from_slice(&(n.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // extra
            if central {
                h.extend_from_slice(&0u16.to_le_bytes()); // comment
                h.extend_from_slice(&0u16.to_le_bytes()); // disk
                h.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
                h.extend_from_slice(&(0o600u32 << 16).to_le_bytes());
                h.extend_from_slice(&off.to_le_bytes());
            }
            h.extend_from_slice(n);
            h
        };
        out.extend(head(0x0403_4b50, false));
        out.extend_from_slice(data);
        central.extend(head(0x0201_4b50, true));
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

pub fn j(v: &Value) -> String {
    dumps(v, Dump::PLAIN)
}

pub fn s(x: &str) -> Value {
    Value::from(x)
}

pub fn verdict(suite: &str, repo: &str, commit: &str, core: &str, status: &str) -> Value {
    Value::Dict(dict([
        ("schema", s("busbar.conformance.verdict/1")),
        ("suite", s(suite)),
        ("status", s(status)),
        ("armed", Value::Bool(true)),
        ("repo", s(repo)),
        ("commit", s(commit)),
        ("core_pin", s(core)),
        (
            "run_id",
            Value::Str(format!("modernci:{repo}@{commit}:conformance")),
        ),
        (
            "evidence",
            Value::Str(format!(
                "{MCI}/move?repo={}&from=dev&head={commit}",
                repo.replace('/', "%2F")
            )),
        ),
        ("generated_at", s("2026-10-28T10:00:00Z")),
    ]))
}

/// The `conformance` check's output archive: verdicts plus the completed invocation receipt.
pub fn invocation_archive(verdicts: &[Value]) -> Vec<u8> {
    let first = verdicts[0].as_dict().unwrap();
    let mut payloads: Vec<(String, Vec<u8>)> = Vec::new();
    for v in verdicts {
        let sid = py::py_str(v.as_dict().unwrap().get("suite").unwrap());
        payloads.push((format!("{sid}.json"), j(v).into_bytes()));
    }
    let failed = verdicts
        .iter()
        .any(|v| !py::eq_str(v.as_dict().unwrap().get("status"), "pass"));
    let receipt = Value::Dict(dict([
        ("schema", s("busbar.conformance.invocation/1")),
        ("invocation_id", s(&"1".repeat(32))),
        ("repo", first.get("repo").unwrap().clone()),
        ("commit", first.get("commit").unwrap().clone()),
        ("core_pin", first.get("core_pin").unwrap().clone()),
        ("started_at", first.get("generated_at").unwrap().clone()),
        ("finished_at", first.get("generated_at").unwrap().clone()),
        ("exit_code", Value::from(failed as i64)),
        (
            "inputs",
            Value::Dict(dict(
                ["run.sh", "tools.sh", "suites.tsv"]
                    .iter()
                    .map(|n| (format!("testing/conformance/{n}"), s(&"a".repeat(64)))),
            )),
        ),
        (
            "verdicts",
            Value::Dict(dict(
                payloads
                    .iter()
                    .map(|(n, d)| (n.clone(), Value::Str(py::sha256_hex(d)))),
            )),
        ),
    ]));
    let mut members: Vec<(String, Vec<u8>)> = payloads
        .into_iter()
        .map(|(n, d)| (format!("target/conformance/verdicts/{n}"), d))
        .collect();
    members.push((
        "target/conformance/invocation.json".into(),
        j(&receipt).into_bytes(),
    ));
    let refs: Vec<(&str, &[u8])> = members
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    tgz(&refs)
}

pub struct World {
    pub dir: PathBuf,
    pub root: PathBuf,
    pub cand: PathBuf,
    pub keys: PathBuf,
    pub state: PathBuf,
    pub bin: PathBuf,
    pub pack: String,
    pub k1_list: String,
    pub release_signer: String,
    pub signer: String,
    pub tag_signer: String,
    pub trust: Value,
    pub commit: String,
    pub kit: String,
    pub index: String,
    pub layout: Vec<(String, Vec<u8>)>,
    /// (repo, head) -> the verdicts ModernCI kept
    pub outputs: Vec<((String, String), Vec<Value>)>,
}

static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl World {
    pub fn new(name: &str, pack: &str) -> World {
        let base = std::env::temp_dir().join("publish-gate-parity");
        std::fs::create_dir_all(&base).unwrap();
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = base.join(format!("{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("repo");
        let cand = dir.join("cand");
        let keys = dir.join("keys");
        let state = dir.join("state");
        let bin = dir.join("bin");
        for d in [&root, &cand, &keys, &state, &bin] {
            std::fs::create_dir_all(d).unwrap();
        }
        for tool in ["docker", "gh", "skopeo", "cosign", "rekor-cli"] {
            std::fs::copy(
                crate_dir().join("tests/fixtures/bin").join(tool),
                bin.join(tool),
            )
            .unwrap();
        }
        // The scanner refuses a database older than its policy allows: it was "downloaded" now.
        std::fs::write(bin.join("docker.updated_at"), now_utc()).unwrap();
        let mut w = World {
            dir,
            root,
            cand,
            keys,
            state,
            bin,
            pack: pack.to_string(),
            k1_list: String::new(),
            release_signer: String::new(),
            signer: String::new(),
            tag_signer: String::new(),
            trust: Value::Null,
            commit: String::new(),
            kit: String::new(),
            index: String::new(),
            layout: Vec::new(),
            outputs: Vec::new(),
        };
        w.keys_and_trust();
        w.repo();
        w.candidate();
        w.state_files();
        w
    }

    fn p256(&self, name: &str) -> String {
        let pem = self.keys.join(format!("{name}.pem"));
        sh(
            &[
                "openssl",
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                pem.to_str().unwrap(),
            ],
            None,
        );
        let der = sh(
            &[
                "openssl",
                "pkey",
                "-in",
                pem.to_str().unwrap(),
                "-pubout",
                "-outform",
                "DER",
            ],
            None,
        );
        format!("p256:{}", py::hex(&der[der.len() - 65..]))
    }

    fn keys_and_trust(&mut self) {
        let k = |n: &str| self.keys.join(n).to_string_lossy().into_owned();
        let root = self.p256("root");
        self.release_signer = self.p256("signer");
        self.k1_list = format!("busbar-plugins-root:{root}");
        std::fs::write(
            k("keys-spec.json"),
            j(&Value::Dict(dict([
                ("version", Value::from(1i64)),
                ("expires", s("2099-01-01T00:00:00Z")),
                ("signers", Value::List(vec![s(&self.release_signer)])),
            ]))),
        )
        .unwrap();
        sh(
            &[
                &self.pack,
                "keys-doc",
                "--spec",
                &k("keys-spec.json"),
                "--out",
                &k("keys.signed"),
            ],
            None,
        );
        sh(
            &[
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                &k("root.pem"),
                "-out",
                &k("keys.sig"),
                &k("keys.signed"),
            ],
            None,
        );
        sh(
            &[
                &self.pack,
                "envelope",
                "--signed",
                &k("keys.signed"),
                "--key",
                &root,
                "--signature",
                &k("keys.sig"),
                "--out",
                &k("keys.json"),
            ],
            None,
        );
        std::fs::write(
            k("k1-sign"),
            format!(
                "#!/bin/sh\nexec openssl dgst -sha256 -sign \"{}\" -out \"$2\" \"$1\"\n",
                k("signer.pem")
            ),
        )
        .unwrap();
        chmod_x(&self.keys.join("k1-sign"));
        sh(
            &[
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "busbar-release-2026a",
                "-f",
                &k("k2"),
            ],
            None,
        );
        let pubkey = std::fs::read_to_string(k("k2.pub")).unwrap();
        let f: Vec<&str> = pubkey.split_whitespace().collect();
        self.signer = format!(
            "busbar-release namespaces=\"busbar-release\" {} {} busbar-release-2026a",
            f[0], f[1]
        );
        self.tag_signer = format!(
            "busbar-release namespaces=\"git\" {} {} busbar-release-2026a",
            f[0], f[1]
        );
        self.trust = Value::Dict(dict([
            ("k1", s(&self.k1_list)),
            ("release_signer", s(&self.release_signer)),
            ("keys_doc", s(&k("keys.json"))),
            (
                "k2_allowed_signers",
                Value::List(vec![s(&self.signer), s(&self.tag_signer)]),
            ),
            (
                "cosign",
                Value::Dict(dict([
                    ("identity", s("release@getbusbar.com")),
                    ("issuer", s("https://accounts.google.com")),
                ])),
            ),
        ]));
        self.save_trust();
    }

    pub fn save_trust(&self) {
        std::fs::write(self.keys.join("trust.json"), j(&self.trust)).unwrap();
    }

    pub fn trust_set(&mut self, k: &str, v: Value) {
        if let Value::Dict(d) = &mut self.trust {
            d.insert(k, v);
        }
        self.save_trust();
    }

    pub fn write(&self, rel: &str, data: impl AsRef<[u8]>) {
        let p = self.dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.dir.join(rel)).unwrap()
    }

    pub fn rm(&self, rel: &str) {
        let p = self.dir.join(rel);
        if p.is_dir() {
            std::fs::remove_dir_all(p).unwrap();
        } else {
            std::fs::remove_file(p).unwrap();
        }
    }

    pub fn git(&self, args: &[&str]) -> String {
        git(&self.root, args)
    }

    fn repo(&mut self) {
        let signers = format!("# K2\n{}\n{}\n", self.signer, self.tag_signer);
        self.write(
            "repo/.cargo/config.toml",
            format!("[env]\nBUSBAR_RELEASE_PUBKEY = \"{}\"\n", self.k1_list),
        );
        self.write(
            "repo/crates/busbar/Cargo.toml",
            format!("[package]\nname = \"busbar\"\nversion = \"{VERSION}\"\n"),
        );
        self.write(
            "repo/CHANGELOG.md",
            format!(
                "# Changelog\n\n## [Unreleased]\n\n## [{VERSION}] - 2026-10-26\n\n## [1.5.5]\n"
            ),
        );
        self.write(
            "repo/plugins.yaml",
            format!(
                "fleet:\n  x: 1\n\nplugins:\n  - repo: {PLUGIN}\n    kind: store\n\nother: 1\n"
            ),
        );
        let targets = r#"{"targets": [
  {"target": "x86_64-unknown-linux-gnu", "kind": "binary", "published": true, "archive": "tar.gz", "packaged_into": ""},
  {"target": "x86_64-pc-windows-msvc", "kind": "binary", "published": true, "archive": "zip", "packaged_into": ""},
  {"target": "x86_64-unknown-linux-musl", "kind": "binary", "published": false, "archive": "tar.gz", "packaged_into": "image-linux-amd64"},
  {"target": "aarch64-unknown-linux-musl", "kind": "binary", "published": false, "archive": "tar.gz", "packaged_into": "image-linux-arm64"},
  {"target": "image-linux-amd64", "kind": "image", "published": false, "archive": "oci"},
  {"target": "image-linux-arm64", "kind": "image", "published": false, "archive": "oci"}
]}"#;
        self.write("repo/release/release-targets.json", targets);
        self.write("repo/release/allowed_signers", signers);
        self.write(
            "repo/release/plugin-pins.tsv",
            format!("# pins\n{PLUGIN}\tv{PVER}\t{PLUGIN_COMMIT}\n"),
        );
        // The scanner policy the trusted checkout carries.
        self.write(
            "repo/ci/security/tools.json",
            r#"{"trivy": "mirror.gcr.io/aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb", "semgrep": "mirror.gcr.io/semgrep/semgrep:1.184.0@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed", "database_max_age_hours": 72}"#,
        );
        for f in [
            "trivy.yaml",
            "trivy.ignore",
            "trivy-secret.yaml",
            "semgrep.yaml",
        ] {
            self.write(&format!("repo/ci/security/{f}"), format!("# {f}\n"));
        }
        self.git(&["init", "-q"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", "kit"]);
        self.kit = self.git(&["rev-parse", "HEAD"]);
        self.git(&["tag", &format!("test-kit-v{VERSION}")]);
        self.write(
            "repo/dist/default/Cargo.lock",
            format!(
                "[[package]]\nname = \"x\"\nsource = \"git+https://github.com/GetBusbar/{PLUGIN}?rev=abc#{PLUGIN_COMMIT}\"\n"
            ),
        );
        self.write(
            "repo/conformance/registry.toml",
            "[[suite]]\nid = \"tls\"\nrepo = \"GetBusbar/busbar\"\nstandard = \"TLS\"\nplan = \"testssl.sh\"\n\
             tier = \"conformant\"\nlabel = \"TLS\"\nverdict = \"conformance-verdict-tls\"\npublic = \"true\"\n\n\
             [[suite]]\nid = \"fake-store\"\nrepo = \"GetBusbar/busbar-store-fake\"\nstandard = \"Store contract\"\n\
             plan = \"store battery\"\ntier = \"capable\"\nlabel = \"Store\"\nverdict = \"conformance-verdict-fake-store\"\n\
             public = \"true\"\n\n\
             [[suite]]\nid = \"sigstore\"\nrepo = \"GetBusbar/busbar\"\nstandard = \"Sigstore\"\nplan = \"cosign verify\"\n\
             tier = \"capable\"\nlabel = \"Sigstore\"\nverdict = \"conformance-verdict-sigstore\"\npublic = \"false\"\n",
        );
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", "release"]);
        self.commit = self.git(&["rev-parse", "HEAD"]);
        let key = self.keys.join("k2");
        self.git(&[
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("user.signingkey={}", key.display()),
            "tag",
            "-s",
            &format!("v{VERSION}"),
            "-m",
            &format!("busbar {VERSION}"),
        ]);
    }

    pub fn binary(&self, tag: &str) -> Vec<u8> {
        format!("\x7fELF busbar {tag} key={} end", self.k1_list).into_bytes()
    }

    pub fn sbom(&self, name: &str) -> String {
        j(&Value::Dict(dict([
            ("bomFormat", s("CycloneDX")),
            ("specVersion", s("1.5")),
            (
                "metadata",
                Value::Dict(dict([(
                    "component",
                    Value::Dict(dict([("name", s(name)), ("version", s(VERSION))])),
                )])),
            ),
            (
                "components",
                Value::List(vec![Value::Dict(dict([
                    ("name", s("fixture-dependency")),
                    ("version", s("1")),
                ]))]),
            ),
        ])))
    }

    fn verifier(&self, target: &str) {
        let exe = format!(
            "busbar-audit-verify{}",
            if target.contains("windows") {
                ".exe"
            } else {
                ""
            }
        );
        let members: [(&str, &[u8]); 2] = [
            (&exe, b"offline verifier"),
            ("audit-verify.md", b"Offline instructions"),
        ];
        if target.contains("windows") {
            self.write(
                &format!("cand/artifacts/busbar-audit-verify-{target}.zip"),
                zip(&members),
            );
        } else {
            self.write(
                &format!("cand/artifacts/busbar-audit-verify-{target}.tar.gz"),
                tgz(&members),
            );
        }
        self.write(
            &format!("cand/sboms/busbar-audit-verify-v{VERSION}-{target}.cdx.json"),
            self.sbom("busbar-audit-verify"),
        );
    }

    pub fn blob(&mut self, data: Vec<u8>) -> String {
        let d = py::sha256_hex(&data);
        self.layout
            .retain(|(n, _)| *n != format!("blobs/sha256/{d}"));
        self.layout.push((format!("blobs/sha256/{d}"), data));
        format!("sha256:{d}")
    }

    pub fn image_index(&mut self, extra: Option<Value>) {
        let musl = [
            ("amd64", self.binary("musl-amd64")),
            ("arm64", self.binary("musl-arm64")),
        ];
        let mut mans = Vec::new();
        for (arch, bin) in musl {
            let layer = {
                use std::io::Write;
                let mut e =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(&raw_tar(&[("busbar", &bin)])).unwrap();
                e.finish().unwrap()
            };
            let ld = self.blob(layer);
            let cfg = self.blob(
                j(&Value::Dict(dict([
                    ("config", Value::Dict(dict([("User", s("65532:65532"))]))),
                    ("architecture", s(arch)),
                    ("os", s("linux")),
                ])))
                .into_bytes(),
            );
            let man = self.blob(
                j(&Value::Dict(dict([
                    ("schemaVersion", Value::from(2i64)),
                    ("config", Value::Dict(dict([("digest", s(&cfg))]))),
                    (
                        "layers",
                        Value::List(vec![Value::Dict(dict([("digest", s(&ld))]))]),
                    ),
                ])))
                .into_bytes(),
            );
            mans.push(Value::Dict(dict([
                ("digest", s(&man)),
                (
                    "platform",
                    Value::Dict(dict([("os", s("linux")), ("architecture", s(arch))])),
                ),
            ])));
        }
        let mut top = dict([
            ("schemaVersion", Value::from(2i64)),
            ("manifests", Value::List(mans)),
        ]);
        if let Some(x) = extra {
            top.insert("annotations", x);
        }
        self.index = self.blob(j(&Value::Dict(top)).into_bytes());
        self.set_index_json(&self.index.clone());
    }

    pub fn set_index_json(&mut self, digest: &str) {
        let body = j(&Value::Dict(dict([
            ("schemaVersion", Value::from(2i64)),
            (
                "manifests",
                Value::List(vec![Value::Dict(dict([("digest", s(digest))]))]),
            ),
        ])));
        self.layout.retain(|(n, _)| n != "index.json");
        self.layout.push(("index.json".into(), body.into_bytes()));
        self.write_layout();
    }

    pub fn write_layout(&self) {
        let refs: Vec<(&str, &[u8])> = self
            .layout
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        self.write("cand/oci/busbar.oci.tar", raw_tar(&refs));
    }

    fn candidate(&mut self) {
        for d in ["artifacts", "sboms", "internal", "plugins", "oci"] {
            std::fs::create_dir_all(self.cand.join(d)).unwrap();
        }
        self.write(
            "cand/artifacts/busbar-x86_64-unknown-linux-gnu.tar.gz",
            tgz(&[("busbar", &self.binary("gnu"))]),
        );
        self.write(
            "cand/artifacts/busbar-x86_64-pc-windows-msvc.zip",
            zip(&[("busbar.exe", &self.binary("win"))]),
        );
        self.write(
            &format!("cand/artifacts/busbar-openapi-v{VERSION}.json"),
            "{}\n",
        );
        for t in ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"] {
            self.verifier(t);
        }
        self.write(
            "cand/internal/busbar-x86_64-unknown-linux-musl.tar.gz",
            tgz(&[("busbar", &self.binary("musl-amd64"))]),
        );
        self.write(
            "cand/internal/busbar-aarch64-unknown-linux-musl.tar.gz",
            tgz(&[("busbar", &self.binary("musl-arm64"))]),
        );
        for t in [
            "x86_64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "image-linux-amd64",
            "image-linux-arm64",
        ] {
            self.write(
                &format!("cand/sboms/busbar-v{VERSION}-{t}.cdx.json"),
                self.sbom("busbar"),
            );
        }
        self.image_index(None);
        self.write("cand/IMAGES", format!("busbar {}\n", self.index));
        let lib = self.dir.join("libfake.so");
        std::fs::write(
            &lib,
            (0..2048u32)
                .map(|i| (i * 7 % 251) as u8)
                .collect::<Vec<u8>>(),
        )
        .unwrap();
        for (target, _, _) in PLUGIN_TARGETS {
            let out = self
                .cand
                .join(format!("plugins/{PLUGIN}-{PVER}-{target}.tar.gz"));
            sh(
                &[
                    &self.pack,
                    "pack",
                    "--lib",
                    lib.to_str().unwrap(),
                    "--name",
                    PLUGIN,
                    "--alias",
                    "fake",
                    "--kind",
                    "store",
                    "--version",
                    PVER,
                    "--publisher",
                    "busbar",
                    "--allow-unsigned",
                    "--out",
                    out.to_str().unwrap(),
                ],
                None,
            );
        }
        self.set_candidate(|_| {});
        self.outputs = vec![
            (
                (CORE.into(), self.commit.clone()),
                vec![verdict("tls", CORE, &self.commit, &self.commit, "pass")],
            ),
            (
                (format!("GetBusbar/{PLUGIN}"), PLUGIN_COMMIT.into()),
                vec![verdict(
                    "fake-store",
                    &format!("GetBusbar/{PLUGIN}"),
                    PLUGIN_COMMIT,
                    &self.commit,
                    "pass",
                )],
            ),
        ];
    }

    /// Rewrite candidate.json from the standard fields, edited by `edit`.
    pub fn set_candidate(&self, edit: impl FnOnce(&mut py::Dict)) {
        let mut cj = dict([
            ("version", s(VERSION)),
            ("commit", s(&self.commit)),
            ("repo", s(CORE)),
            (
                "test_kit",
                Value::Dict(dict([
                    ("tag", s(&format!("test-kit-v{VERSION}"))),
                    ("commit", s(&self.kit)),
                ])),
            ),
            (
                "plugins",
                Value::List(vec![Value::Dict(dict([
                    ("repo", s(PLUGIN)),
                    ("version", s(PVER)),
                    ("tag", s(&format!("v{PVER}"))),
                    ("commit", s(PLUGIN_COMMIT)),
                ]))]),
            ),
        ]);
        edit(&mut cj);
        self.write("cand/candidate.json", j(&Value::Dict(cj)));
    }

    fn state_files(&self) {
        self.write("state/busbar-ref", format!("{} {VERSION}\n", self.kit));
        self.write(
            "state/dev_heads.json",
            j(&Value::Dict(dict([(
                format!("GetBusbar/{PLUGIN}"),
                s(PLUGIN_COMMIT),
            )]))),
        );
    }

    /// The release index, as the candidate renders it (the gate's own renderer).
    pub fn render_index(&self) {
        let spec = self.spec("index", "fixture", |d| {
            d.insert(
                "out",
                Value::Str(
                    self.cand
                        .join("artifacts/plugin-index.json")
                        .to_string_lossy()
                        .into(),
                ),
            );
        });
        let o = run_cmd(
            Command::new(harness()).arg(&spec),
            &self.root,
            &self.bin,
            &self.dir.join("tmp-fixture"),
        );
        assert_eq!(o.code, 0, "index render failed: {}{}", o.stdout, o.stderr);
    }

    pub fn sums(&self) {
        let mut files: Vec<PathBuf> = Vec::new();
        for d in ["artifacts", "sboms"] {
            for e in std::fs::read_dir(self.cand.join(d)).unwrap() {
                files.push(e.unwrap().path());
            }
        }
        files.sort_by_key(|f| f.file_name().unwrap().to_owned());
        let mut text = String::new();
        for f in files {
            text.push_str(&format!(
                "{}  {}\n",
                py::sha256_file(&f).unwrap(),
                f.file_name().unwrap().to_string_lossy()
            ));
        }
        self.write("cand/SHA256SUMS", text);
    }

    /// The conformance-manifest slice: ModernCI's outputs fetched into the candidate, and the
    /// manifest rendered from them.
    pub fn conformance(&self) {
        let _ = std::fs::remove_dir_all(self.cand.join("conformance"));
        let pins = [
            (CORE.to_string(), self.commit.clone()),
            (format!("GetBusbar/{PLUGIN}"), PLUGIN_COMMIT.to_string()),
        ];
        for (repo, head) in pins {
            let d = self.cand.join("conformance").join(&repo);
            std::fs::create_dir_all(&d).unwrap();
            let mut rec = dict([
                ("repo", s(&repo)),
                ("check", s("conformance")),
                ("head", s(&head)),
            ]);
            match self
                .outputs
                .iter()
                .find(|(k, _)| *k == (repo.clone(), head.clone()))
            {
                None => rec.insert(
                    "missing",
                    s(&format!(
                        "no check result or measurement of conformance at {head} kept outputs"
                    )),
                ),
                Some((_, verdicts)) => {
                    let data = invocation_archive(verdicts);
                    let green = verdicts
                        .iter()
                        .all(|v| py::eq_str(v.as_dict().unwrap().get("status"), "pass"));
                    let generation = "generation-fixture";
                    let g = d.join(generation);
                    std::fs::create_dir_all(g.join("verdicts")).unwrap();
                    std::fs::write(g.join("artifact.tar"), &data).unwrap();
                    for v in verdicts {
                        let sid = py::py_str(v.as_dict().unwrap().get("suite").unwrap());
                        std::fs::write(
                            g.join("verdicts").join(format!("{sid}.json")),
                            dumps(v, Dump::SORTED) + "\n",
                        )
                        .unwrap();
                    }
                    rec.insert("from", s("dev"));
                    rec.insert("state", s(if green { "green" } else { "red" }));
                    rec.insert("sha", Value::Str(py::sha256_hex(&data)));
                    rec.insert("generation", s(generation));
                }
            }
            std::fs::write(
                d.join("receipt.json"),
                dumps(&Value::Dict(rec), Dump::SORTED) + "\n",
            )
            .unwrap();
        }
        self.render_manifest();
    }

    pub fn render_manifest(&self) {
        let pins = busbar_publish_gate::conformance::shipped_pins(&self.root).unwrap();
        let exc = busbar_publish_gate::conformance::read_exceptions(&self.root, VERSION).unwrap();
        let text = busbar_publish_gate::conformance::render_release(
            &self.root.join("conformance/registry.toml"),
            &self.cand.join("conformance"),
            VERSION,
            &self.commit,
            &pins,
            &exc,
            None,
        )
        .unwrap();
        self.write("cand/conformance-manifest.json", text);
    }

    /// Index, sums and conformance: the candidate as `assemble` leaves it.
    pub fn finish(&self) {
        self.render_index();
        self.sums();
        self.conformance();
    }

    pub fn spec(&self, command: &str, security: &str, edit: impl FnOnce(&mut py::Dict)) -> PathBuf {
        let mut d = dict([
            ("command", s(command)),
            ("root", s(&self.root.to_string_lossy())),
            ("cand", s(&self.cand.to_string_lossy())),
            ("trust", s(&self.keys.join("trust.json").to_string_lossy())),
            ("pack", s(&self.pack)),
            ("out", s(&self.dir.join("out").to_string_lossy())),
            ("state", s(&self.state.to_string_lossy())),
            ("require_hardware_k2", Value::Bool(false)),
            ("security", s(security)),
            ("confirm", s(&self.commit[..12])),
            (
                "k1_sign_cmd",
                s(&self.keys.join("k1-sign").to_string_lossy()),
            ),
            ("k2_key", s(&self.keys.join("k2").to_string_lossy())),
        ]);
        edit(&mut d);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = self.dir.join(format!("spec-{n}.json"));
        std::fs::write(&p, j(&Value::Dict(d))).unwrap();
        p
    }
}

/// The current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn chmod_x(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

pub fn harness() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/harness")
}

pub struct Outcome {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_cmd(c: &mut Command, cwd: &Path, bin: &Path, tmp: &Path) -> Outcome {
    std::fs::create_dir_all(tmp).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = c
        .current_dir(cwd)
        .env("PATH", path)
        .env("TMPDIR", tmp)
        .output()
        .unwrap();
    Outcome {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}
