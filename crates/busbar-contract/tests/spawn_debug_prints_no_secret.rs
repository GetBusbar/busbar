// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A program to spawn carries its arguments and its whole environment; neither is allowed to reach
//! a log line through `Debug` (Aikido group 58995487, #111).

use busbar_contract::io_host::Spawn;

const TOKEN: &str = "sk-live-8f2b1c";
const ARG_SECRET: &str = "--api-key=hunter2hunter2";

fn spawned() -> Spawn<'static> {
    Spawn {
        program: "/usr/local/bin/grid-server",
        args: &["--pipe", ARG_SECRET],
        env: &[("GRID_API_TOKEN", TOKEN), ("HOME", "/var/empty")],
    }
}

#[test]
fn a_spawns_debug_names_the_program_and_never_an_argument_or_an_env_value() {
    let rendered = format!("{:?}", spawned());

    assert!(
        !rendered.contains(TOKEN),
        "an environment value reached a log line: {rendered}"
    );
    assert!(
        !rendered.contains("/var/empty"),
        "every environment value is withheld: {rendered}"
    );
    assert!(
        !rendered.contains("hunter2"),
        "an argument reached a log line: {rendered}"
    );

    assert!(rendered.contains("Spawn"), "{rendered}");
    assert!(
        rendered.contains("/usr/local/bin/grid-server"),
        "{rendered}"
    );
    assert!(rendered.contains("GRID_API_TOKEN"), "{rendered}");
    assert!(rendered.contains("HOME"), "{rendered}");
    assert!(
        rendered.contains(&format!("<{} bytes>", TOKEN.len())),
        "{rendered}"
    );
}

#[test]
fn a_spawn_with_no_arguments_and_no_environment_says_so() {
    let bare = Spawn {
        program: "/bin/true",
        args: &[],
        env: &[],
    };
    let rendered = format!("{bare:?}");
    assert!(rendered.contains("/bin/true"), "{rendered}");
    assert!(rendered.contains("args: []"), "{rendered}");
    assert!(rendered.contains("env: []"), "{rendered}");
}
