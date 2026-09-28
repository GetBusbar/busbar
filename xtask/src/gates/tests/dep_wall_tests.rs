// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn the_ledger_reads_carriers_and_pins_and_refuses_anything_else() {
    let l = read_ledger("# note\ncarrier\tbusbar-transport-tcp\nbusbar-llm\trustls\nnonsense\n");
    assert!(l.carriers.contains("busbar-transport-tcp"));
    assert!(l.pinned.contains(&("busbar-llm".into(), "rustls".into())));
    assert_eq!(l.errors.len(), 1);
}

#[test]
fn asking_tokio_for_net_or_redis_for_aio_is_an_offence() {
    let p = Pkg {
        name: "x".into(),
        source: None,
        manifest_path: String::new(),
        deps: vec![
            ("tokio".into(), vec!["net".into()], false, true),
            ("redis".into(), vec!["tokio-comp".into()], false, true),
            ("tokio".into(), vec!["net".into()], false, false),
        ],
        features: BTreeMap::new(),
    };
    assert_eq!(asks(&p), ["tokio (net)", "redis (aio)"]);
}
