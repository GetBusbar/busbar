// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! TEST HARNESS ONLY: runs one gate command against a fixture world, with every read-only lookup
//! (GitHub, the registries, ModernCI) answered from files under the world's `state/` directory.
//! Only this harness can relax the hardware-K2 check; the `busbar-publish-gate` CLI cannot. It is
//! an example, so `cargo build` never builds it and nothing ships it.
//!
//!   harness <spec.json>
//!
//! spec.json: {"command", "root", "cand", "trust", "pack", "out", "state", "require_hardware_k2",
//! "security": "real"|"fixture", "confirm": str|null, "k1_sign_cmd", "k2_key", "repo", "tag",
//! "plugins"}.

use busbar_publish_gate::gate::{self, Inputs};
use busbar_publish_gate::py::{self, dict, Kind, PyErr, Value, R};
use busbar_publish_gate::security::RealSecurity;
use busbar_publish_gate::world::{ModernCI, Net, Security};
use std::io::Write;
use std::path::{Path, PathBuf};

struct StateNet(PathBuf);

fn mangle(r: &str) -> String {
    r.replace(['/', ':'], "_")
}

fn map_get(file: &Path, key: &str) -> R<Option<String>> {
    if !py::is_file(file) {
        return Ok(None);
    }
    let v = py::loads(&py::read_text(file)?)?;
    Ok(v.get(key)?.and_then(Value::as_str).map(str::to_string))
}

impl Net for StateNet {
    fn release_exists(&self, repo: &str, tag: &str) -> R<bool> {
        Ok(py::is_dir(&self.0.join("releases").join(repo).join(tag)))
    }
    fn release_published(&self, repo: &str, tag: &str) -> R<bool> {
        Ok(py::is_file(
            &self
                .0
                .join("releases")
                .join(repo)
                .join(tag)
                .join(".published"),
        ))
    }
    fn registry_digest(&self, reference: &str) -> R<Option<String>> {
        let f = self.0.join("registry").join(mangle(reference));
        Ok(if py::is_file(&f) {
            Some(py::read_text(&f)?)
        } else {
            None
        })
    }
    fn repo_full_name(&self, repo: &str) -> R<Option<String>> {
        map_get(&self.0.join("full_names.json"), repo)
    }
    fn remote_tag(&self, repo: &str, tag: &str) -> R<Option<String>> {
        map_get(&self.0.join("remote_tags.json"), &format!("{repo} {tag}"))
    }
    fn repo_file(&self, _repo: &str, _path: &str, _reference: &str) -> R<String> {
        py::read_text(&self.0.join("busbar-ref"))
    }
}

struct StateMCI(PathBuf);

impl ModernCI for StateMCI {
    fn dev_head(&self, repo: &str) -> R<String> {
        map_get(&self.0.join("dev_heads.json"), repo)?
            .ok_or_else(|| PyErr::new(Kind::CgCannotRun, format!("no dev head for {repo}")))
    }
}

struct FixtureSecurity;

impl Security for FixtureSecurity {
    fn scan_candidate(&self, _: &Path, _: &Path, _: &[String]) -> R<Value> {
        Ok(Value::Dict(dict([
            ("schema", Value::from("busbar.artifact-security/1")),
            ("status", Value::from("pass")),
        ])))
    }
    fn scan_plugin_candidate(
        &self,
        _: &Path,
        _: &Path,
        _: &[String],
        _: &str,
        _: &str,
        _: &str,
    ) -> R<Value> {
        Ok(Value::Dict(dict([("status", Value::from("pass"))])))
    }
}

fn report(e: PyErr) -> i32 {
    if e.kind == Kind::CannotRun {
        println!("CANNOT RUN: {}", e.msg);
        println!("publish-gate: a rule could not run; this is never a pass.");
        return 3;
    }
    if e.is_os() || e.is_value() || e.is_key() {
        println!("CANNOT RUN: {}: {}", e.name(), e.msg);
        return 3;
    }
    let _ = std::io::stdout().flush();
    eprintln!("harness: uncaught {}: {}", e.name(), e.msg);
    1
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: harness <spec.json>");
    let spec = py::loads(&py::read_text(Path::new(&path)).expect("spec")).expect("spec JSON");
    let get = |k: &str| -> String {
        spec.get(k)
            .ok()
            .flatten()
            .map(py::py_str)
            .unwrap_or_default()
    };
    let state = PathBuf::from(get("state"));
    let net = StateNet(state.clone());
    let mci = StateMCI(state);
    let fixture = get("security") == "fixture";
    let security: &dyn Security = if fixture {
        &FixtureSecurity
    } else {
        &RealSecurity
    };
    let confirm = spec
        .get("confirm")
        .ok()
        .flatten()
        .and_then(Value::as_str)
        .map(str::to_string);
    let input = move |prompt: &str| -> Option<String> {
        print!("{prompt}");
        let _ = std::io::stdout().flush();
        confirm.clone()
    };
    let code = (|| -> R<i32> {
        let trust = gate::load_trust(Path::new(&get("trust")))?;
        let inp = Inputs {
            root: PathBuf::from(get("root")),
            cand: PathBuf::from(get("cand")),
            trust,
            pack: get("pack"),
            net: &net,
            require_hardware_k2: spec
                .get("require_hardware_k2")
                .ok()
                .flatten()
                .map(Value::truthy)
                .unwrap_or(true),
            mci: &mci,
            security,
            input: &input,
        };
        let out = PathBuf::from(get("out"));
        match get("command").as_str() {
            "verify" => gate::cmd_verify(&inp, &out),
            "sign" => gate::cmd_sign(&inp, &out, &get("k1_sign_cmd"), &get("k2_key")),
            "upload" => gate::cmd_upload(&inp, &out),
            "plugin-release" => gate::cmd_plugin_release(
                &inp,
                &out,
                &get("repo"),
                &get("tag"),
                Path::new(&get("plugins")),
                &get("k1_sign_cmd"),
                &get("k2_key"),
            ),
            "index" => {
                let cj = py::loads(&py::read_text(&inp.cand.join("candidate.json"))?)?;
                let bytes = gate::render_plugin_index(
                    &inp.root,
                    &inp.cand,
                    &cj.item("plugins")?.iter_items()?,
                    inp.net,
                )?;
                py::write_bytes(&out, &bytes)?;
                Ok(0)
            }
            other => panic!("unknown harness command {other}"),
        }
    })()
    .unwrap_or_else(report);
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}
