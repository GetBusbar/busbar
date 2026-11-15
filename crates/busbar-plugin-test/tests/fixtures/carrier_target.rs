// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A routes-only host target, run as its own process by `tests/target_carrier.rs`: `main`'s
//! command line, ready file, verdict and exit code. `/hello` answers which image took it and for
//! which caller; `/unserved` answers that it is not served, which fails the run.

use busbar_plugin_test::target::carrier::{Reply, Request, Routes};
use busbar_plugin_test::target::Target;

fn main() -> std::process::ExitCode {
    Target::new(
        Routes::new()
            .route("GET", "/hello", |req: Request| {
                let who = req.caller().map_or("nobody", |c| c.name());
                Reply::ok(format!("hello from {} to {who}", req.image()))
            })
            .route("GET", "/unserved", |_: Request| {
                Reply::unserved("the fixture's unserved route")
            }),
    )
    .main()
}
