// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ORACLE'S STORE BACKENDS NEVER TAKE A PINNED PORT. A wire-exact capture cell pins its mock's
//! port (cells.json `capture.mock.port`, 24733 for wire.h1|stream|anthropic): the 1.5.5 golden
//! records that host port, so the mock must get exactly it. The store harness
//! (testing/shadow-oracle/scripts/oracle-box-store-services.sh) is handed random ports by the oracle
//! check; one that lands on a pinned port is refused and replaced by a free port no cell pins, before
//! any container starts. RED before: valkey started on :24733 and the wire cell failed ("capture
//! mock port 24733 is not free").

use std::path::Path;
use std::process::Command;

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The store harness's `env` (no docker): its export lines and what it said, for these ports.
fn env_for(pg: u16, my: u16, vk: u16) -> (String, String) {
    let out = Command::new("bash")
        .arg(root().join("testing/shadow-oracle/scripts/oracle-box-store-services.sh"))
        .arg("env")
        .env("ORACLE_PG_PORT", pg.to_string())
        .env("ORACLE_MY_PORT", my.to_string())
        .env("ORACLE_VK_PORT", vk.to_string())
        .current_dir(root())
        .output()
        .expect("bash runs the store harness");
    assert!(out.status.success(), "{out:?}");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Every port a capture cell pins.
fn pinned() -> Vec<u16> {
    let cells: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("testing/shadow-oracle/cells.json")).expect("cells"),
    )
    .expect("cells.json parses");
    cells["cells"]
        .as_array()
        .expect("cells")
        .iter()
        .filter_map(|c| c["capture"]["mock"]["port"].as_u64())
        .map(|p| u16::try_from(p).expect("a port"))
        .collect()
}

#[test]
fn a_store_port_on_a_pinned_capture_port_is_refused_and_replaced() {
    let pinned = pinned();
    assert!(
        pinned.contains(&24733),
        "wire.h1|stream|anthropic pins 24733"
    );
    for &p in &pinned {
        let (exports, said) = env_for(p, p, p);
        for line in exports.lines() {
            assert!(
                !line.contains(&format!(":{p}/")),
                "a store URL kept the pinned port {p}: {line}"
            );
            for q in &pinned {
                assert!(!line.contains(&format!(":{q}/")), "{line} takes pinned {q}");
            }
        }
        assert_eq!(
            said.matches(&format!("port :{p} is pinned by a wire-exact capture cell"))
                .count(),
            3,
            "each of the three stores says it was refused :{p}: {said}"
        );
    }
}

#[test]
fn a_store_port_no_cell_pins_is_kept() {
    let (exports, said) = env_for(31001, 31002, 31003);
    assert!(exports.contains("127.0.0.1:31001/"), "{exports}");
    assert!(exports.contains("127.0.0.1:31002/"), "{exports}");
    assert!(exports.contains("127.0.0.1:31003/"), "{exports}");
    assert!(!said.contains("is pinned"), "{said}");
}
