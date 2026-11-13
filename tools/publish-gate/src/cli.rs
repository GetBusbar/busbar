// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The command line. It builds only the real lookups and always requires a hardware K2.

use crate::gate::{self, Inputs, EXIT_CANNOT_RUN, EXIT_OK, EXIT_USAGE};
use crate::py::{self, Kind, PyErr, R};
use crate::security::RealSecurity;
use crate::world::{self, RealModernCI, RealNet};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

pub const USAGE: &str = "usage:
  busbar-publish-gate verify          --candidate DIR --trust FILE --pack BIN --out DIR
  busbar-publish-gate sign            --candidate DIR --trust FILE --pack BIN --out DIR --k1-sign-cmd CMD --k2-key FILE
  busbar-publish-gate upload          --candidate DIR --trust FILE --pack BIN --out DIR
  busbar-publish-gate plugin-release  REPO TAG --plugins DIR --trust FILE --pack BIN --out DIR --k1-sign-cmd CMD --k2-key FILE
  busbar-publish-gate spot-rebuild    TARGET --candidate DIR --trust FILE --pack BIN --out DIR
  busbar-publish-gate plugin-index    --candidate DIR --plugins FILE --out FILE

Run from your own clone at the release commit, with busbar-plugin-pack built there by you.
--k1-sign-cmd is the RELEASE SIGNER, called ONCE per release as `CMD <release-manifest-file> <signature-out>`;
it writes the raw signature (DER for P-256): scripts/release/sign-*.sh (docs/design/release-trust.md).
--k2-key is the ed25519-sk key handle (`ssh-keygen -K` writes it from the YubiKey).
plugin-index writes the release index (artifacts/plugin-index.json) for the plugins in FILE (a JSON list of
{repo, version, tag, commit}) from DIR/plugins; it is how the candidate writes the bytes G-3 re-renders.";

fn need(cmd: &str) -> Option<&'static [&'static str]> {
    Some(match cmd {
        "verify" | "upload" | "spot-rebuild" => &["candidate", "trust", "pack", "out"],
        "sign" => &["candidate", "trust", "pack", "out", "k1-sign-cmd", "k2-key"],
        "plugin-release" => &["plugins", "trust", "pack", "out", "k1-sign-cmd", "k2-key"],
        "plugin-index" => &["candidate", "plugins", "out"],
        _ => return None,
    })
}

fn read_line(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches('\n').to_string()),
    }
}

fn expanduser(p: &str) -> String {
    if p == "~" || p.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!(
                "{}{}",
                home.to_string_lossy().trim_end_matches('/'),
                &p[1..]
            );
        }
    }
    p.to_string()
}

/// A failure the gate did not turn into a refusal. "Could not run" is exit 3 and never a pass;
/// anything else is an internal error, exit 1, with nothing signed or published.
fn report(e: PyErr) -> i32 {
    if e.kind == Kind::CannotRun {
        println!("CANNOT RUN: {}", e.msg);
        println!("publish-gate: a rule could not run; this is never a pass.");
        return EXIT_CANNOT_RUN;
    }
    if e.is_os() || e.is_value() || e.is_key() {
        println!("CANNOT RUN: {}: {}", e.name(), e.msg);
        return EXIT_CANNOT_RUN;
    }
    internal(&e)
}

fn internal(e: &PyErr) -> i32 {
    let _ = std::io::stdout().flush();
    eprintln!("publish-gate: internal error: {}: {}", e.name(), e.msg);
    eprintln!("publish-gate: nothing was signed or published by this step.");
    1
}

fn plugin_index(opts: &[(String, Option<String>)]) -> R<i32> {
    let get = |k: &str| {
        opts.iter()
            .find(|(x, _)| x == k)
            .and_then(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let root = toplevel()?;
    let plugins = py::loads(&py::read_text(Path::new(&py::norm(&get("plugins"))))?)?;
    let list = plugins.iter_items()?;
    let bytes = gate::render_plugin_index(
        &root,
        Path::new(&py::norm(&get("candidate"))),
        &list,
        &RealNet,
    )?;
    py::write_bytes(Path::new(&py::norm(&get("out"))), &bytes)?;
    Ok(EXIT_OK)
}

fn toplevel() -> R<PathBuf> {
    let out = world::run(
        &["git".into(), "rev-parse".into(), "--show-toplevel".into()],
        None,
        true,
    )?;
    Ok(PathBuf::from(py::norm(py::strip(&out.stdout_str()?))))
}

pub fn main(argv: &[String]) -> i32 {
    if argv.is_empty() || argv[0] == "-h" || argv[0] == "--help" {
        println!("{USAGE}");
        return if argv.is_empty() { EXIT_USAGE } else { EXIT_OK };
    }
    let cmd = argv[0].as_str();
    let mut pos: Vec<String> = Vec::new();
    let mut opts: Vec<(String, Option<String>)> = Vec::new();
    let mut it = argv[1..].iter();
    while let Some(a) = it.next() {
        if let Some(k) = a.strip_prefix("--") {
            if opts.iter().any(|(x, _)| x == k) {
                println!("--{k} given twice\n{USAGE}");
                return EXIT_USAGE;
            }
            opts.push((k.to_string(), it.next().cloned()));
        } else {
            pos.push(a.clone());
        }
    }
    let Some(need) = need(cmd) else {
        println!("{USAGE}");
        return EXIT_USAGE;
    };
    let get = |k: &str| -> Option<String> {
        opts.iter()
            .find(|(x, _)| x == k)
            .and_then(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    };
    if need.iter().any(|k| get(k).is_none())
        || opts.iter().any(|(k, _)| !need.contains(&k.as_str()))
    {
        println!("{USAGE}");
        return EXIT_USAGE;
    }
    if cmd == "plugin-index" {
        return plugin_index(&opts).unwrap_or_else(report);
    }
    // The clone the rules and keys are read from. Not being in one is not a gate decision.
    let root = match toplevel() {
        Ok(r) => r,
        Err(e) => return internal(&e),
    };
    let net = RealNet;
    let mci = RealModernCI { root: root.clone() };
    let security = RealSecurity;
    let run = || -> R<i32> {
        let trust = gate::load_trust(Path::new(&py::norm(&expanduser(&get("trust").unwrap()))))?;
        let inp = Inputs {
            root: root.clone(),
            cand: PathBuf::from(py::norm(&get("candidate").unwrap_or_else(|| ".".into()))),
            trust,
            pack: get("pack").unwrap(),
            net: &net,
            require_hardware_k2: true,
            mci: &mci,
            security: &security,
            input: &read_line,
        };
        let out = PathBuf::from(py::norm(&get("out").unwrap()));
        match cmd {
            "verify" => gate::cmd_verify(&inp, &out),
            "sign" => gate::cmd_sign(
                &inp,
                &out,
                &get("k1-sign-cmd").unwrap(),
                &get("k2-key").unwrap(),
            ),
            "upload" => gate::cmd_upload(&inp, &out),
            "plugin-release" => {
                if pos.len() != 2 {
                    println!("{USAGE}");
                    return Ok(EXIT_USAGE);
                }
                gate::cmd_plugin_release(
                    &inp,
                    &out,
                    &pos[0],
                    &pos[1],
                    Path::new(&py::norm(&get("plugins").unwrap())),
                    &get("k1-sign-cmd").unwrap(),
                    &get("k2-key").unwrap(),
                )
            }
            "spot-rebuild" => {
                if pos.len() != 1 {
                    println!("{USAGE}");
                    return Ok(EXIT_USAGE);
                }
                gate::cmd_spot_rebuild(&inp, &out, &pos[0])
            }
            _ => Ok(EXIT_USAGE),
        }
    };
    match run() {
        Ok(code) => code,
        Err(e) => report(e),
    }
}
