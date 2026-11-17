// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The C-FIPS-GATE probe (tests/fips_gate.rs): the facade over the stub backend, at run time. One
//! `key=value` line per answer; the test reads them.

fn main() {
    let mut buf = [0_u8; 16];
    println!("fill_checked={:?}", busbar_crypto::fill_checked(&mut buf));
    println!("fill={:?}", busbar_crypto::fill(&mut buf));
    println!("external_plugins={}", busbar_crypto::EXTERNAL_PLUGINS);
    println!(
        "supports_external_plugins={}",
        busbar_crypto::supports("EXTERNAL_PLUGINS")
    );
    println!(
        "supports_md5={}",
        busbar_crypto::supports(busbar_crypto::alg::MD5)
    );
    println!("backend={}", busbar_crypto::BACKEND);
    println!("checked_hash={:?}", busbar_crypto::verification::Context::unrestricted().sha256(b"abc"));
    println!("validation={:?}", busbar_crypto::VALIDATION);
    println!("validated_mode={}", busbar_crypto::VALIDATED_MODE);
}
