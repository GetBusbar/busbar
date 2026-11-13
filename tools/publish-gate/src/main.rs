// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! busbar-publish-gate: see the library documentation and `--help`.

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(busbar_publish_gate::cli::main(&argv));
}
