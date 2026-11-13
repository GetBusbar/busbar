// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Every decision and message of the gate, over a fixture world per case: a good release that
//! verifies, signs and uploads, and one broken thing at a time, each refused with its rule.
//!
//! Each case's exit code and output must equal tests/golden/<case>.txt, which records what the
//! original Python gate (scripts/release/publish_gate.py) said over the same world. While that
//! Python is in the tree, each case also runs it (tests/differential/py_gate.py) and requires the
//! same exit code, the same output and the same evidence bytes from both.
//!
//! Needs busbar-plugin-pack ($PACK, or the repo's target/{debug,release}), openssl, ssh-keygen
//! and git. `UPDATE_GOLDEN=1` rewrites the golden files from the Python gate's output.

mod support;

use busbar_publish_gate::py::{self, Dict, Value};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;
use support::*;

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        let t = to.join(e.file_name());
        if p.is_dir() {
            copy_dir(&p, &t);
        } else {
            std::fs::copy(&p, &t).unwrap();
        }
    }
}

fn files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(base: &Path, d: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.push(p.strip_prefix(base).unwrap().to_string_lossy().into_owned());
            }
        }
    }
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Paths and temporary names, which differ between the two runs over one world.
fn local(w: &World, text: &str) -> String {
    let d = w.dir.to_string_lossy().into_owned();
    let t = text
        .replace(&format!("{d}/out-py"), "<OUT>")
        .replace(&format!("{d}/out-rs"), "<OUT>");
    let t = Regex::new(&format!(
        r"{}/tmp-(py|rs)/[A-Za-z0-9_.-]+",
        regex::escape(&d)
    ))
    .unwrap()
    .replace_all(&t, "<TMP>")
    .into_owned();
    let t = t.replace(&d, "<W>");
    // The release manifest's version is the signing time, and its digest covers it.
    Regex::new(r"version=[0-9]+ entries=([0-9]+) signed-sha256=[0-9a-f]{64}")
        .unwrap()
        .replace_all(
            &t,
            "version=<SIGNING TIME> entries=$1 signed-sha256=<FRESH>",
        )
        .into_owned()
}

/// Keys, digests and commits, which differ between worlds.
fn golden(text: &str) -> String {
    let t = Regex::new(r"SHA256:[A-Za-z0-9+/]{43}")
        .unwrap()
        .replace_all(text, "<FP>")
        .into_owned();
    let t = Regex::new(r"AAAA[A-Za-z0-9+/]{16,}=*")
        .unwrap()
        .replace_all(&t, "<KEY>")
        .into_owned();
    let t = Regex::new(r"p256:[0-9a-f]+")
        .unwrap()
        .replace_all(&t, "p256:<HEX>")
        .into_owned();
    let t = Regex::new(r"[0-9a-f]{12,}")
        .unwrap()
        .replace_all(&t, "<HEX>")
        .into_owned();
    Regex::new(r"\b1[0-9]{9}\b")
        .unwrap()
        .replace_all(&t, "<TIME>")
        .into_owned()
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    out: PathBuf,
}

fn side(w: &World, spec: &Path, py_side: bool, out: &Path) -> Run {
    let tag = if py_side { "py" } else { "rs" };
    let _ = std::fs::remove_dir_all(&w.state);
    copy_dir(&w.dir.join("state.orig"), &w.state);
    let _ = std::fs::remove_dir_all(out);
    let signed = w.dir.join("out-signed");
    if signed.is_dir() {
        copy_dir(&signed, out);
    }
    let text = std::fs::read_to_string(spec).unwrap().replace(
        &w.dir.join("out").to_string_lossy().into_owned(),
        &out.to_string_lossy(),
    );
    let spec2 = w.dir.join(format!("spec-{tag}.json"));
    std::fs::write(&spec2, text).unwrap();
    let mut c = if py_side {
        let mut c = Command::new("python3");
        c.arg(python().unwrap());
        c
    } else {
        Command::new(harness())
    };
    c.arg(&spec2);
    let o = run_cmd(&mut c, &w.root, &w.bin, &w.dir.join(format!("tmp-{tag}")));
    Run {
        code: o.code,
        stdout: o.stdout,
        stderr: o.stderr,
        out: out.to_path_buf(),
    }
}

/// Files whose bytes carry a fresh signature or the signing time, so differ run to run.
fn fresh(name: &str) -> bool {
    name.ends_with(".sig")
        || name.starts_with("signed/")
        || name == "release-manifest.json"
        || name == "SHA256SUMS.plugins"
        || name == "released.tsv"
}

fn evidence_view(name: &str, bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let masked = |keys: &[&str]| -> String {
        let mut v = py::loads(&text).unwrap();
        if let Value::Dict(d) = &mut v {
            for k in keys {
                if d.contains(k) {
                    d.insert(*k, Value::from("<fresh>"));
                }
            }
        }
        py::dumps(&v, py::Dump::SORTED)
    };
    match name {
        "release-evidence.json" => masked(&["plugin_release_manifest", "sha256sums_plugins"]),
        "plugin-security.json" => masked(&["signed_artifacts"]),
        // A plugin release's sums list freshly sealed tarballs and evidence: compare the names.
        "SHA256SUMS" => text
            .lines()
            .map(|l| l.split_whitespace().last().unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => text,
    }
}

fn compare_outputs(name: &str, rs: &Run, pyr: &Run) {
    let (a, b) = (files(&rs.out), files(&pyr.out));
    assert_eq!(a, b, "{name}: the two gates wrote different files");
    for f in &a {
        if fresh(f) {
            continue;
        }
        let x = std::fs::read(rs.out.join(f)).unwrap();
        let y = std::fs::read(pyr.out.join(f)).unwrap();
        if x != y {
            assert_eq!(
                evidence_view(f, &x),
                evidence_view(f, &y),
                "{name}: {f} differs between the Rust and Python gates"
            );
        }
    }
}

fn record(_name: &str, code: i32, text: &str) -> String {
    format!("exit {code}\n{}", golden(text))
}

fn check_golden(name: &str, got: &str, python_said: Option<&str>) {
    let path = crate_dir().join("tests/golden").join(format!("{name}.txt"));
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        let said = python_said.expect("UPDATE_GOLDEN needs the Python gate in the tree");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, said).unwrap();
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{name}: no golden file {}", path.display()));
    assert_eq!(
        got, want,
        "{name}: output differs from the recorded Python gate"
    );
}

/// Run `command` over the world with both gates and require one answer.
fn judge(name: &str, w: &World, command: &str, security: &str, edit: impl FnOnce(&mut Dict)) {
    if !w.dir.join("state.orig").is_dir() {
        copy_dir(&w.state, &w.dir.join("state.orig"));
    }
    let spec = w.spec(command, security, edit);
    let rs = side(w, &spec, false, &w.dir.join("out-rs"));
    let rs_text = local(w, &rs.stdout);
    let mine = record(name, rs.code, &rs_text);
    let mut python_said = None;
    if python().is_some() {
        let pyr = side(w, &spec, true, &w.dir.join("out-py"));
        let py_text = local(w, &pyr.stdout);
        assert_eq!(
            (pyr.code, &py_text),
            (rs.code, &rs_text),
            "{name}: Python and Rust gates disagree\n--- python stderr\n{}\n--- rust stderr\n{}",
            pyr.stderr,
            rs.stderr
        );
        compare_outputs(name, &rs, &pyr);
        python_said = Some(record(name, pyr.code, &py_text));
    }
    check_golden(name, &mine, python_said.as_deref());
    let _ = std::fs::remove_dir_all(&w.dir);
}

fn world(name: &str) -> Option<World> {
    let Some(pack) = pack() else {
        eprintln!("{name}: skipped, no busbar-plugin-pack (set PACK)");
        return None;
    };
    let w = World::new(name, &pack);
    w.finish();
    Some(w)
}

macro_rules! case {
    ($name:ident, $cmd:expr, $sec:expr, |$w:ident| $setup:block) => {
        case!($name, $cmd, $sec, |$w| $setup, |_d| {});
    };
    ($name:ident, $cmd:expr, $sec:expr, |$w:ident| $setup:block, |$d:ident| $edit:block) => {
        #[test]
        fn $name() {
            let Some(w0) = world(stringify!($name)) else { return };
            #[allow(unused_mut)]
            let mut $w = w0;
            $setup
            judge(stringify!($name), &$w, $cmd, $sec, |$d| $edit);
        }
    };
}

// ── verify: the good release and each refusal ──────────────────────────────────────────────────

case!(a_good_release_verifies, "verify", "real", |w| {});

case!(g0_candidate_json_missing, "verify", "real", |w| {
    w.rm("cand/candidate.json");
});

case!(g0_candidate_json_malformed, "verify", "real", |w| {
    w.write("cand/candidate.json", "{\"version\": \"1.6.0\",}");
});

case!(g0_candidate_json_lacks_a_field, "verify", "real", |w| {
    w.set_candidate(|cj| {
        cj.0.retain(|(k, _)| k != "test_kit");
    });
});

case!(g1_clone_not_at_the_release_commit, "verify", "real", |w| {
    w.git(&["commit", "-q", "--allow-empty", "-m", "x"]);
});

case!(g1_changelog_behind, "verify", "real", |w| {
    w.write("repo/CHANGELOG.md", "## [1.5.5]\n");
});

case!(g1_cargo_version_differs, "verify", "real", |w| {
    w.write(
        "repo/crates/busbar/Cargo.toml",
        "[package]\nname = \"busbar\"\nversion = \"1.6.1\"\n",
    );
});

case!(g1_a_fork_with_a_short_commit, "verify", "real", |w| {
    w.set_candidate(|cj| {
        cj.insert("repo", Value::from("someone/busbar"));
        cj.insert("commit", Value::from("abc"));
    });
});

case!(g2_already_published, "verify", "real", |w| {
    std::fs::create_dir_all(w.state.join("releases/GetBusbar/busbar/v1.6.0")).unwrap();
});

case!(g2_registry_tag_holds_another_image, "verify", "real", |w| {
    w.write(
        "state/registry/ghcr.io_getbusbar_busbar_1.6.0",
        format!("sha256:{}", "0".repeat(64)),
    );
});

case!(g2_plugin_release_already_published, "verify", "real", |w| {
    w.write(
        "state/releases/GetBusbar/busbar-store-fake/v1.6.0/.published",
        "",
    );
});

case!(g3_missing_target_is_named, "verify", "real", |w| {
    w.rm("cand/artifacts/busbar-x86_64-pc-windows-msvc.zip");
    w.sums();
});

case!(g3_undeclared_file_is_refused, "verify", "real", |w| {
    w.write("cand/artifacts/extra.bin", "x");
    w.sums();
});

case!(g3_plugin_missing_from_candidate, "verify", "real", |w| {
    w.write(
        "repo/plugins.yaml",
        format!("plugins:\n  - repo: {PLUGIN}\n  - repo: busbar-auth-other\n"),
    );
});

case!(g3_pins_file_malformed, "verify", "real", |w| {
    w.write(
        "repo/release/plugin-pins.tsv",
        format!("{PLUGIN}\tv{PVER}\n"),
    );
});

case!(
    g3_candidate_plugin_differs_from_the_pins,
    "verify",
    "real",
    |w| {
        w.set_candidate(|cj| {
        cj.insert(
            "plugins",
            py::loads(&format!(
                "[{{\"repo\": \"{PLUGIN}\", \"version\": \"{PVER}\", \"tag\": \"v{PVER}\", \"commit\": \"{}\"}}]",
                "d".repeat(40)
            ))
            .unwrap(),
        );
    });
    }
);

case!(g3_wrong_plugin_version, "verify", "real", |w| {
    w.set_candidate(|cj| {
        cj.insert(
            "plugins",
            py::loads(&format!(
                "[{{\"repo\": \"{PLUGIN}\", \"version\": \"1.6.1\", \"tag\": \"v{PVER}\", \"commit\": \"{PLUGIN_COMMIT}\"}}]"
            ))
            .unwrap(),
        );
    });
});

case!(g3_an_edited_index_is_refused, "verify", "real", |w| {
    let f = "cand/artifacts/plugin-index.json";
    w.write(f, w.read(f).replace("\"v1.6.0\"", "\"v9.9.9\""));
    w.sums();
});

case!(g3_a_missing_index_is_refused, "verify", "real", |w| {
    w.rm("cand/artifacts/plugin-index.json");
    w.sums();
});

case!(g3_an_index_that_cannot_render, "verify", "real", |w| {
    w.write(
        &format!("cand/plugins/{PLUGIN}-{PVER}-x86_64-unknown-linux-gnu.tar.gz"),
        tgz(&[("libfake.so", b"lib")]),
    );
});

case!(g4_bytes_changed_after_the_sums, "verify", "real", |w| {
    w.write("cand/artifacts/busbar-openapi-v1.6.0.json", "{\"x\":1}\n");
});

case!(g4_malformed_sums, "verify", "real", |w| {
    w.write("cand/SHA256SUMS", "nonsense\n");
});

case!(g4_missing_sums, "verify", "real", |w| {
    w.rm("cand/SHA256SUMS");
});

case!(g5_a_tarball_that_is_not_a_plugin, "verify", "real", |w| {
    w.write(
        &format!("cand/plugins/{PLUGIN}-{PVER}-aarch64-apple-darwin.tar.gz"),
        "not a tarball",
    );
});

case!(g6_binary_without_the_key_list, "verify", "real", |w| {
    w.write(
        "cand/artifacts/busbar-x86_64-unknown-linux-gnu.tar.gz",
        tgz(&[("busbar", b"no key here")]),
    );
    w.sums();
});

case!(g6_an_unreadable_archive, "verify", "real", |w| {
    w.write(
        "cand/artifacts/busbar-x86_64-unknown-linux-gnu.tar.gz",
        "garbage bytes, not a tar",
    );
    w.sums();
});

case!(g6_a_windows_zip_with_two_binaries, "verify", "real", |w| {
    let b = w.binary("win");
    w.write(
        "cand/artifacts/busbar-x86_64-pc-windows-msvc.zip",
        zip(&[("busbar.exe", &b), ("bin/busbar.exe", &b)]),
    );
    w.sums();
});

case!(
    g6_a_verifier_package_with_an_extra_file,
    "verify",
    "real",
    |w| {
        w.write(
            "cand/artifacts/busbar-audit-verify-x86_64-unknown-linux-gnu.tar.gz",
            tgz(&[
                ("busbar-audit-verify", b"offline verifier"),
                ("audit-verify.md", b"Offline instructions"),
                ("extra", b"x"),
            ]),
        );
        w.sums();
    }
);

case!(
    g6_a_verifier_zip_without_instructions,
    "verify",
    "real",
    |w| {
        w.write(
            "cand/artifacts/busbar-audit-verify-x86_64-pc-windows-msvc.zip",
            zip(&[("busbar-audit-verify.exe", b"offline verifier")]),
        );
        w.sums();
    }
);

case!(g8_sbom_for_another_version, "verify", "real", |w| {
    w.write(
        "cand/sboms/busbar-v1.6.0-x86_64-unknown-linux-gnu.cdx.json",
        "{\"bomFormat\": \"CycloneDX\", \"metadata\": {\"component\": {\"version\": \"1.5.5\"}}}",
    );
    w.sums();
});

case!(g8_sbom_that_is_not_json, "verify", "real", |w| {
    w.write(
        "cand/sboms/busbar-v1.6.0-image-linux-arm64.cdx.json",
        "{\"bomFormat\": \n",
    );
    w.sums();
});

case!(
    g9_unverified_provenance_is_never_published,
    "verify",
    "real",
    |w| {
        std::fs::create_dir_all(w.cand.join("provenance")).unwrap();
    }
);

case!(g10_image_binary_differs, "verify", "real", |w| {
    let b = w.binary("other");
    w.write(
        "cand/internal/busbar-x86_64-unknown-linux-musl.tar.gz",
        tgz(&[("busbar", &b)]),
    );
});

case!(
    g10_images_file_names_another_digest,
    "verify",
    "real",
    |w| {
        w.write("cand/IMAGES", format!("busbar sha256:{}\n", "1".repeat(64)));
    }
);

case!(g10_an_unreadable_oci_archive, "verify", "real", |w| {
    w.write("cand/oci/busbar.oci.tar", "not an oci layout");
});

case!(g10_an_index_with_two_descriptors, "verify", "real", |w| {
    let body = format!(
        "{{\"schemaVersion\": 2, \"manifests\": [{{\"digest\": \"{0}\"}}, {{\"digest\": \"{0}\"}}]}}",
        w.index
    );
    w.layout.retain(|(n, _)| n != "index.json");
    w.layout.push(("index.json".into(), body.into_bytes()));
    w.write_layout();
});

case!(g11_linked_plugin_pin_differs, "verify", "real", |w| {
    let f = "repo/dist/default/Cargo.lock";
    w.write(f, w.read(f).replace(PLUGIN_COMMIT, &"d".repeat(40)));
    w.git(&["commit", "-qam", "x"]);
    let head = w.git(&["rev-parse", "HEAD"]);
    w.set_candidate(|cj| cj.insert("commit", Value::Str(head.clone())));
});

case!(g12_plugin_pinned_to_another_core, "verify", "real", |w| {
    w.write("state/busbar-ref", format!("{}\n", "e".repeat(40)));
});

case!(g12_test_kit_tag_wrong, "verify", "real", |w| {
    w.set_candidate(|cj| {
        cj.insert(
            "test_kit",
            py::loads("{\"tag\": \"test-kit-v9\", \"commit\": \"\"}").unwrap(),
        );
    });
});

case!(
    g13_a_differing_second_build_is_reported,
    "verify",
    "real",
    |w| {
        w.write(
            "cand/rebuild/artifacts/busbar-openapi-v1.6.0.json",
            "{\"rebuilt\": true}\n",
        );
    }
);

case!(
    g14_key_list_not_in_the_owners_trust_file,
    "verify",
    "real",
    |w| {
        w.trust_set(
            "k1",
            Value::Str(format!("busbar-plugins-root:{}", "ab".repeat(32))),
        );
    }
);

case!(g14_k2_line_without_a_namespace, "verify", "real", |w| {
    let line = w.signer.replace("namespaces=\"busbar-release\" ", "");
    w.trust_set(
        "k2_allowed_signers",
        Value::List(vec![Value::Str(line.clone())]),
    );
    w.write("repo/release/allowed_signers", format!("{line}\n"));
});

case!(g14_k2_line_with_two_namespaces, "verify", "real", |w| {
    let line = w.signer.replace(
        "namespaces=\"busbar-release\"",
        "namespaces=\"busbar-release,busbar-release-statement\"",
    );
    let tag = w.tag_signer.clone();
    w.trust_set(
        "k2_allowed_signers",
        Value::List(vec![Value::Str(line.clone()), Value::Str(tag.clone())]),
    );
    w.write("repo/release/allowed_signers", format!("{line}\n{tag}\n"));
});

case!(
    g14_software_k2_refused_by_the_real_rule,
    "verify",
    "real",
    |w| {},
    |d| {
        d.insert("require_hardware_k2", Value::Bool(true));
    }
);

case!(
    g14_committed_allowed_signers_differ,
    "verify",
    "real",
    |w| {
        let f = "repo/release/allowed_signers";
        w.write(f, w.read(f) + "busbar-release namespaces=\"git\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherOtherOtherOtherOtherOtherOtherOth x\n");
    }
);

case!(g15_no_version_tag, "verify", "real", |w| {
    w.git(&["tag", "-d", "v1.6.0"]);
});

case!(g15_a_lightweight_tag, "verify", "real", |w| {
    w.git(&["tag", "-d", "v1.6.0"]);
    w.git(&["tag", "v1.6.0"]);
});

case!(g15_an_unsigned_annotated_tag, "verify", "real", |w| {
    w.git(&["tag", "-d", "v1.6.0"]);
    w.git(&["tag", "-a", "v1.6.0", "-m", "busbar 1.6.0"]);
});

case!(g15_a_tag_signed_by_another_key, "verify", "real", |w| {
    let other = w.keys.join("other");
    sh(
        &[
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "other",
            "-f",
            other.to_str().unwrap(),
        ],
        None,
    );
    w.git(&["tag", "-d", "v1.6.0"]);
    w.git(&[
        "-c",
        "gpg.format=ssh",
        "-c",
        &format!("user.signingkey={}", other.display()),
        "tag",
        "-s",
        "v1.6.0",
        "-m",
        "busbar 1.6.0",
    ]);
});

case!(g15_a_git_line_for_another_key, "verify", "real", |w| {
    let other = w.keys.join("other");
    sh(
        &[
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "other",
            "-f",
            other.to_str().unwrap(),
        ],
        None,
    );
    let p = std::fs::read_to_string(w.keys.join("other.pub")).unwrap();
    let f: Vec<&str> = p.split_whitespace().collect();
    let git_line = format!("busbar-release namespaces=\"git\" {} {} other", f[0], f[1]);
    let file_line = w.signer.clone();
    w.trust_set(
        "k2_allowed_signers",
        Value::List(vec![
            Value::Str(file_line.clone()),
            Value::Str(git_line.clone()),
        ]),
    );
    w.write(
        "repo/release/allowed_signers",
        format!("{file_line}\n{git_line}\n"),
    );
});

case!(gc_a_public_suite_without_a_pass, "verify", "real", |w| {
    let c = w.commit.clone();
    w.outputs[0].1 = vec![verdict("tls", CORE, &c, &c, "fail")];
    w.conformance();
});

case!(gc_a_hand_edited_manifest, "verify", "real", |w| {
    w.outputs.clear();
    w.conformance();
    let f = "cand/conformance-manifest.json";
    w.write(f, w.read(f).replace("\"not-run\"", "\"pass\""));
});

case!(gc_a_missing_manifest, "verify", "real", |w| {
    w.rm("cand/conformance-manifest.json");
});

case!(gc_a_plugin_with_no_output, "verify", "real", |w| {
    w.outputs.truncate(1);
    w.conformance();
});

case!(gc_a_pin_that_is_not_the_dev_head, "verify", "real", |w| {
    w.write(
        "state/dev_heads.json",
        format!("{{\"GetBusbar/{PLUGIN}\": \"{}\"}}", "f".repeat(40)),
    );
});

case!(gc_an_unsigned_exception, "verify", "real", |w| {
    w.write(
        "repo/release/conformance-exceptions.json",
        "{\"schema\": \"busbar.conformance.exceptions/1\", \"release\": \"1.6.0\", \"suites\": []}",
    );
});

case!(gc_a_signed_exception_is_honoured, "verify", "real", |w| {
    let c = w.commit.clone();
    w.outputs[0].1 = vec![verdict("tls", CORE, &c, &c, "fail")];
    w.write(
        "repo/release/conformance-exceptions.json",
        "{\"schema\": \"busbar.conformance.exceptions/1\", \"release\": \"1.6.0\", \
         \"suites\": [{\"suite\": \"tls\", \"status\": \"fail\", \"reason\": \"grade B, accepted\"}, {\"suite\": \"x\", \"status\": \"pass\"}], \
         \"pins\": [{\"repo\": \"busbar-store-fake\", \"commit\": \"bad\"}]}",
    );
    let f = w.root.join("release/conformance-exceptions.json");
    sh(
        &[
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            w.keys.join("k2").to_str().unwrap(),
            "-n",
            "busbar-release",
            f.to_str().unwrap(),
        ],
        None,
    );
    w.conformance();
});

case!(
    gc_a_signed_exception_lets_a_recorded_failure_ship,
    "verify",
    "real",
    |w| {
        let c = w.commit.clone();
        w.outputs[0].1 = vec![verdict("tls", CORE, &c, &c, "fail")];
        w.write(
        "repo/release/conformance-exceptions.json",
        "{\"schema\": \"busbar.conformance.exceptions/1\", \"release\": \"1.6.0\", \
         \"suites\": [{\"suite\": \"tls\", \"status\": \"fail\", \"reason\": \"grade B, accepted\"}]}",
    );
        let f = w.root.join("release/conformance-exceptions.json");
        sh(
            &[
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                w.keys.join("k2").to_str().unwrap(),
                "-n",
                "busbar-release",
                f.to_str().unwrap(),
            ],
            None,
        );
        w.conformance();
    }
);

case!(
    gc_a_signed_pin_exception_ships_an_older_pin,
    "verify",
    "real",
    |w| {
        w.write(
            "state/dev_heads.json",
            format!("{{\"GetBusbar/{PLUGIN}\": \"{}\"}}", "f".repeat(40)),
        );
        w.write(
        "repo/release/conformance-exceptions.json",
        format!(
            "{{\"schema\": \"busbar.conformance.exceptions/1\", \"release\": \"1.6.0\", \"suites\": [], \
             \"pins\": [{{\"repo\": \"{PLUGIN}\", \"commit\": \"{PLUGIN_COMMIT}\", \"reason\": \"dev moved after the freeze\"}}]}}"
        ),
    );
        let f = w.root.join("release/conformance-exceptions.json");
        sh(
            &[
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                w.keys.join("k2").to_str().unwrap(),
                "-n",
                "busbar-release",
                f.to_str().unwrap(),
            ],
            None,
        );
    }
);

case!(
    g3_an_index_naming_former_repos_verifies,
    "verify",
    "real",
    |w| {
        w.write(
        "repo/plugins.yaml",
        format!(
            "plugins:\n  - repo: {PLUGIN}\n    kind: store\n    alias: fake\n    crate: {PLUGIN}-plugin\n    \
             former_names: [{PLUGIN}-plugin, busbar-fake-db]\n  - repo: busbar-auth-empty\n    kind: auth\n    pending_crate: true\n"
        ),
    );
        w.write(
        "state/full_names.json",
        format!("{{\"GetBusbar/store-fake\": \"GetBusbar/{PLUGIN}\", \"GetBusbar/fake-db\": \"getbusbar/{PLUGIN}\"}}"),
    );
        w.render_index();
        w.sums();
    }
);

case!(
    gs_a_scanner_finding_stops_the_release,
    "verify",
    "real",
    |w| {
        std::fs::write(w.bin.join("docker.mode"), "finding").unwrap();
    }
);

case!(
    gs_a_scanner_image_with_another_digest,
    "verify",
    "real",
    |w| {
        std::fs::write(w.bin.join("docker.mode"), "wrong-digest").unwrap();
    }
);

case!(gs_a_stale_vulnerability_database, "verify", "real", |w| {
    std::fs::write(w.bin.join("docker.updated_at"), "2000-01-01T00:00:00Z").unwrap();
});

case!(trust_file_without_a_key, "verify", "real", |w| {
    if let Value::Dict(d) = &mut w.trust {
        d.0.retain(|(k, _)| k != "keys_doc");
    }
    w.save_trust();
});

// ── sign ────────────────────────────────────────────────────────────────────────────────────────

case!(
    sign_seals_every_plugin_with_one_signature,
    "sign",
    "real",
    |w| {}
);

case!(
    sign_refuses_without_the_typed_commit,
    "sign",
    "real",
    |w| {},
    |d| {
        d.insert("confirm", Value::from("nope"));
    }
);

case!(
    sign_stops_at_the_end_of_input,
    "sign",
    "real",
    |w| {},
    |d| {
        d.insert("confirm", Value::Null);
    }
);

case!(sign_refuses_a_broken_candidate, "sign", "real", |w| {
    w.write("repo/CHANGELOG.md", "## [1.5.5]\n");
});

// ── upload ──────────────────────────────────────────────────────────────────────────────────────

/// Sign the world once (Rust gate) into out-signed/, and put the signed tag on "GitHub".
fn signed(w: &World) {
    copy_dir(&w.state, &w.dir.join("state.orig"));
    let spec = w.spec("sign", "fixture", |d| {
        d.insert(
            "out",
            Value::Str(w.dir.join("out-signed").to_string_lossy().into_owned()),
        );
    });
    let o = run_cmd(
        Command::new(harness()).arg(&spec),
        &w.root,
        &w.bin,
        &w.dir.join("tmp-sign"),
    );
    assert_eq!(
        o.code, 0,
        "signing the fixture failed: {}{}",
        o.stdout, o.stderr
    );
    let local_tag = w.git(&["rev-parse", "refs/tags/v1.6.0"]);
    w.write(
        "state.orig/remote_tags.json",
        format!("{{\"GetBusbar/busbar v1.6.0\": \"{local_tag}\"}}"),
    );
}

case!(
    upload_publishes_the_verified_release,
    "upload",
    "fixture",
    |w| {
        signed(&w);
    }
);

case!(
    upload_refuses_a_missing_signed_download,
    "upload",
    "fixture",
    |w| {
        signed(&w);
        w.write(
            "state.orig/missing",
            "busbar-x86_64-unknown-linux-gnu.tar.gz",
        );
    }
);

case!(
    upload_refuses_replayed_validly_signed_metadata,
    "upload",
    "fixture",
    |w| {
        signed(&w);
        let sums = w.read("out-signed/SHA256SUMS");
        let older: String = sums
            .lines()
            .filter(|l| !l.ends_with("busbar-x86_64-unknown-linux-gnu.tar.gz"))
            .map(|l| format!("{l}\n"))
            .collect();
        let alt = w.dir.join("older/SHA256SUMS");
        w.write("older/SHA256SUMS", older);
        sh(
            &[
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                w.keys.join("k2").to_str().unwrap(),
                "-n",
                "busbar-release",
                alt.to_str().unwrap(),
            ],
            None,
        );
        w.write(
            "state.orig/replace/SHA256SUMS",
            std::fs::read(&alt).unwrap(),
        );
        w.write(
            "state.orig/replace/SHA256SUMS.sig",
            std::fs::read(w.dir.join("older/SHA256SUMS.sig")).unwrap(),
        );
    }
);

case!(
    upload_refuses_signed_images_of_another_candidate,
    "upload",
    "fixture",
    |w| {
        signed(&w);
        w.image_index(Some(Value::Dict(py::dict([(
            "org.opencontainers.image.description",
            Value::from("revised candidate"),
        )]))));
        w.write("cand/IMAGES", format!("busbar {}\n", w.index));
    }
);

case!(
    upload_refuses_before_the_tag_is_on_github,
    "upload",
    "fixture",
    |w| {
        signed(&w);
        w.rm("state.orig/remote_tags.json");
    }
);

case!(
    upload_refuses_an_unsigned_release,
    "upload",
    "fixture",
    |w| {}
);

// ── plugin-release ──────────────────────────────────────────────────────────────────────────────

fn plugin_dir(w: &World) -> PathBuf {
    let d = w.dir.join("plugin-dl");
    std::fs::create_dir_all(&d).unwrap();
    let mut subjects = Vec::new();
    for (target, _, _) in busbar_publish_gate::gate::PLUGIN_TARGETS {
        let name = format!("{PLUGIN}-{PVER}-{target}.tar.gz");
        std::fs::copy(w.cand.join("plugins").join(&name), d.join(&name)).unwrap();
        let sbom = format!("{target}.cdx.json");
        let body = format!(
            "{{\"bomFormat\": \"CycloneDX\", \"metadata\": {{\"component\": {{\"name\": \"{PLUGIN}\", \"version\": \"{PVER}\"}}}}, \"components\": [{{\"name\": \"dep\", \"version\": \"1\"}}]}}"
        );
        std::fs::write(d.join(&sbom), &body).unwrap();
        subjects.push(format!(
            "{{\"artifact\": \"{name}\", \"artifact_sha256\": \"{}\", \"sbom\": \"{sbom}\", \"sbom_sha256\": \"{}\"}}",
            py::sha256_file(&d.join(&name)).unwrap(),
            py::sha256_hex(body.as_bytes())
        ));
    }
    std::fs::write(
        d.join("security-sboms.json"),
        format!(
            "{{\"schema\": \"busbar.plugin-sboms/1\", \"repository\": \"GetBusbar/{PLUGIN}\", \"version\": \"{PVER}\", \"source\": \"{PLUGIN_COMMIT}\", \"subjects\": [{}]}}",
            subjects.join(", ")
        ),
    )
    .unwrap();
    d
}

fn plugin_spec(w: &World, d: &mut Dict, tag: &str, repo: &str) {
    d.insert("repo", Value::from(repo));
    d.insert("tag", Value::from(tag));
    d.insert(
        "plugins",
        Value::Str(w.dir.join("plugin-dl").to_string_lossy().into_owned()),
    );
}

macro_rules! plugin_case {
    ($name:ident, $tag:expr, $repo:expr, |$w:ident| $setup:block) => {
        #[test]
        fn $name() {
            let Some(w0) = world(stringify!($name)) else { return };
            #[allow(unused_mut)]
            let mut $w = w0;
            plugin_dir(&$w);
            $setup
            let wref = &$w;
            judge(stringify!($name), wref, "plugin-release", "real", |d| {
                plugin_spec(wref, d, $tag, $repo)
            });
        }
    };
}

plugin_case!(
    plugin_release_publishes_one_plugin,
    "v1.6.0",
    PLUGIN,
    |w| {}
);
plugin_case!(
    plugin_release_refuses_an_unversioned_tag,
    "1.6.0",
    PLUGIN,
    |w| {}
);
plugin_case!(
    plugin_release_refuses_an_unregistered_plugin,
    "v1.6.0",
    "busbar-auth-other",
    |w| {}
);
plugin_case!(
    plugin_release_refuses_an_unpinned_tag,
    "v1.6.1",
    PLUGIN,
    |w| {}
);
plugin_case!(
    plugin_release_refuses_a_missing_target,
    "v1.6.0",
    PLUGIN,
    |w| {
        w.rm(&format!(
            "plugin-dl/{PLUGIN}-{PVER}-x86_64-apple-darwin.tar.gz"
        ));
    }
);
plugin_case!(
    plugin_release_refuses_a_published_version,
    "v1.6.0",
    PLUGIN,
    |w| {
        w.write(
            "state/releases/GetBusbar/busbar-store-fake/v1.6.0/.published",
            "",
        );
    }
);
plugin_case!(
    plugin_release_needs_matching_sbom_scans,
    "v1.6.0",
    PLUGIN,
    |w| {
        w.rm("plugin-dl/security-sboms.json");
    }
);

// ── the command line ────────────────────────────────────────────────────────────────────────────

fn cli(name: &str, args: &[&str], cwd_in_repo: bool, trust_edit: impl FnOnce(&mut World)) {
    let Some(mut w) = world(name) else { return };
    trust_edit(&mut w);
    let cwd = if cwd_in_repo {
        w.root.clone()
    } else {
        w.dir.clone()
    };
    let fill = |a: &str| {
        a.replace("{trust}", &w.keys.join("trust.json").to_string_lossy())
            .replace("{cand}", &w.cand.to_string_lossy())
            .replace("{out}", &w.dir.join("out").to_string_lossy())
    };
    let args: Vec<String> = args.iter().map(|a| fill(a)).collect();
    let usage_rs = Regex::new(r"(?s)usage:\n.*?G-3 re-renders\.").unwrap();
    let usage_py = Regex::new(r"(?s)usage:\n.*?from the YubiKey\)\.").unwrap();
    let rs = run_cmd(
        Command::new(env!("CARGO_BIN_EXE_busbar-publish-gate")).args(&args),
        &cwd,
        &w.bin,
        &w.dir.join("tmp-rs"),
    );
    let rs_text = local(&w, &usage_rs.replace_all(&rs.stdout, "<USAGE>"));
    let mine = record(name, rs.code, &rs_text);
    let mut python_said = None;
    if python().is_some() {
        let gate = crate_dir().join("../../scripts/release/publish_gate.py");
        let pyr = run_cmd(
            Command::new("python3").arg(gate).args(&args),
            &cwd,
            &w.bin,
            &w.dir.join("tmp-py"),
        );
        let py_text = local(&w, &usage_py.replace_all(&pyr.stdout, "<USAGE>"));
        assert_eq!(
            (pyr.code, &py_text),
            (rs.code, &rs_text),
            "{name}: Python and Rust CLIs disagree\n{}\n{}",
            pyr.stderr,
            rs.stderr
        );
        python_said = Some(record(name, pyr.code, &py_text));
    }
    check_golden(name, &mine, python_said.as_deref());
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn cli_without_arguments() {
    cli("cli_without_arguments", &[], true, |_| {});
}

#[test]
fn cli_help() {
    cli("cli_help", &["--help"], true, |_| {});
}

#[test]
fn cli_unknown_command() {
    cli(
        "cli_unknown_command",
        &["publish", "--trust", "{trust}"],
        true,
        |_| {},
    );
}

#[test]
fn cli_an_option_given_twice() {
    cli(
        "cli_an_option_given_twice",
        &["verify", "--out", "a", "--out", "b"],
        true,
        |_| {},
    );
}

#[test]
fn cli_a_missing_option() {
    cli(
        "cli_a_missing_option",
        &[
            "verify",
            "--candidate",
            "{cand}",
            "--trust",
            "{trust}",
            "--out",
            "{out}",
        ],
        true,
        |_| {},
    );
}

#[test]
fn cli_an_unknown_option() {
    cli(
        "cli_an_unknown_option",
        &[
            "verify",
            "--candidate",
            "{cand}",
            "--trust",
            "{trust}",
            "--pack",
            "x",
            "--out",
            "{out}",
            "--skip",
            "G-1",
        ],
        true,
        |_| {},
    );
}

#[test]
fn cli_a_trust_file_without_k1() {
    cli(
        "cli_a_trust_file_without_k1",
        &[
            "verify",
            "--candidate",
            "{cand}",
            "--trust",
            "{trust}",
            "--pack",
            "x",
            "--out",
            "{out}",
        ],
        true,
        |w| {
            if let Value::Dict(d) = &mut w.trust {
                d.0.retain(|(k, _)| k != "k1");
            }
            w.save_trust();
        },
    );
}

#[test]
fn cli_plugin_release_without_its_arguments() {
    cli(
        "cli_plugin_release_without_its_arguments",
        &[
            "plugin-release",
            "--plugins",
            "x",
            "--trust",
            "{trust}",
            "--pack",
            "x",
            "--out",
            "{out}",
            "--k1-sign-cmd",
            "x",
            "--k2-key",
            "x",
        ],
        true,
        |_| {},
    );
}

#[test]
fn cli_outside_a_clone() {
    cli(
        "cli_outside_a_clone",
        &[
            "verify",
            "--candidate",
            "{cand}",
            "--trust",
            "{trust}",
            "--pack",
            "x",
            "--out",
            "{out}",
        ],
        false,
        |_| {},
    );
}

#[test]
fn cli_the_real_cli_requires_a_hardware_k2() {
    cli(
        "cli_the_real_cli_requires_a_hardware_k2",
        &[
            "verify",
            "--candidate",
            "{cand}",
            "--trust",
            "{trust}",
            "--pack",
            "x",
            "--out",
            "{out}",
        ],
        true,
        |_| {},
    );
}
