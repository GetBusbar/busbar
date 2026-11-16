// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A stream host target over the facade's own line framer, run as its own process by
//! `tests/target_stream.rs`: `main`'s command line, ready file and exit code, and the `--mutant`
//! leg. Its mutant flips the first wire byte of the first EMIT (§11.6); with
//! `FRAMER_TARGET_MUTANT=failing-ready` it is one whose READY fails instead.

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

mod framer_door;

use busbar_contract::abi::transport::slot;
use busbar_plugin_test::target::stream::Framer;
use busbar_plugin_test::target::Target;
use busbar_plugin_test::{Host, Mutant};

fn main() -> std::process::ExitCode {
    let failing = std::env::var_os("FRAMER_TARGET_MUTANT").is_some_and(|v| v == "failing-ready");
    let mutant = if failing {
        Mutant::of(framer_door::door).failing_ready("fixture: never ready")
    } else {
        Mutant::corrupting(framer_door::door, slot::EMIT, 1)
    };
    Target::new(
        Framer::new("framer_fixture", framer_door::door, || {
            Host::new(busbar_contract::services::test_caller_binding())
        })
        .mutant(mutant),
    )
    .main()
}
