// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

mod audit_verify;

use std::path::PathBuf;

const USAGE: &str = "busbar-audit-verify --keys TRUSTED_KEYS.json --range RANGE.json [--trusted-head RETAINED_HEAD.json]\n\
Offline verification of the published audit range. Keys must be trusted independently.\n\
Only an independently retained terminal head establishes completeness through that head.\n\
The range's own anchor never establishes external trust. See docs/audit-verify.md.";

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("{USAGE}");
        return std::process::ExitCode::SUCCESS;
    }
    if args.len() == 1 && args[0] == "--version" {
        println!("busbar-audit-verify {}", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    match run(args) {
        Ok(report) => {
            println!("{report}");
            std::process::ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("busbar-audit-verify: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<std::ffi::OsString>) -> Result<busbar_contract::json::Value, &'static str> {
    let mut keys = None;
    let mut range = None;
    let mut head = None;
    let mut args = lexopt::Parser::from_args(args);
    while let Some(flag) = args.next().map_err(|_| USAGE)? {
        let slot = match flag {
            lexopt::Arg::Long("keys") => &mut keys,
            lexopt::Arg::Long("range") => &mut range,
            lexopt::Arg::Long("trusted-head") => &mut head,
            _ => return Err(USAGE),
        };
        if slot.is_some() {
            return Err("a file option was repeated");
        }
        *slot = Some(PathBuf::from(args.value().map_err(|_| USAGE)?));
    }
    let keys = read_json(keys.ok_or(USAGE)?)?;
    let range = read_json(range.ok_or(USAGE)?)?;
    let head = head.map(read_json).transpose()?;
    audit_verify::verify(&keys, &range, head.as_ref())
}

fn read_json(path: PathBuf) -> Result<busbar_contract::json::Value, &'static str> {
    let file = std::fs::File::open(path).map_err(|_| "could not open an input file")?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::BufReader::new(file), &mut bytes)
        .map_err(|_| "an input file is not valid JSON")?;
    busbar_contract::json::parse_value(&bytes).map_err(|_| "an input file is not valid JSON")
}
