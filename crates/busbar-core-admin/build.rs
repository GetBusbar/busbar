// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Gzips `src/v1/json/openapi.json` into `OUT_DIR` so the served document is embedded
//! compressed without a committed `.gz` artifact. flate2's default header carries no
//! mtime and no filename, so the output is a pure function of the JSON.

use std::io::Write;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/v1/json/openapi.json");
    println!("cargo:rerun-if-changed=build.rs");
    let json = std::fs::read("src/v1/json/openapi.json").expect("read src/v1/json/openapi.json");
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(&json).expect("gzip openapi.json");
    let gz = enc.finish().expect("finish gzip of openapi.json");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"))
        .join("openapi.json.gz");
    std::fs::write(&out, gz).expect("write openapi.json.gz into OUT_DIR");
}
