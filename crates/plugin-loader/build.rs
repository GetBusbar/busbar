// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

fn main() {
    println!(
        "cargo:rustc-env=BUSBAR_PLUGIN_TARGET={}",
        std::env::var("TARGET").expect("cargo sets TARGET for build scripts")
    );
}
