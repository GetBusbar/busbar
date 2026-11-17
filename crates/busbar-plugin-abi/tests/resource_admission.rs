// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_plugin_abi::records::{Reply, Writer};
use busbar_plugin_abi::resource_admission::{
    DescriptorEcho, Scope, decode_echo, decode_selection, write_echo, write_selection,
};

#[test]
fn resource_selection_round_trip_preserves_kind_and_value() {
    let scopes = [
        Scope {
            kind: "pool",
            value: "chat",
        },
        Scope {
            kind: "agent",
            value: "chat",
        },
    ];
    let mut out = Reply::new();
    write_selection(&mut out, &scopes).unwrap();
    assert_eq!(decode_selection(out.as_bytes()).unwrap(), scopes);
}

#[test]
fn empty_duplicate_unknown_and_control_resource_facts_refuse() {
    assert!(decode_selection(&[]).is_err());
    let mut out = Reply::new();
    let scope = Scope {
        kind: "pool",
        value: "chat",
    };
    write_selection(&mut out, &[scope, scope]).unwrap();
    assert!(decode_selection(out.as_bytes()).is_err());
    let mut unknown = Reply::new();
    unknown.put(0x017f, &[]).unwrap();
    assert!(decode_selection(unknown.as_bytes()).is_err());
    let mut invalid = Reply::new();
    write_selection(
        &mut invalid,
        &[Scope {
            kind: "pool",
            value: "chat\nsecret",
        }],
    )
    .unwrap();
    assert!(decode_selection(invalid.as_bytes()).is_err());
}

#[test]
fn descriptor_echo_retains_complete_invocation_route_generation_binding() {
    let echo = DescriptorEcho {
        invocation: u64::MAX,
        generation: 9,
        route: 3,
        descriptor: 7,
        instance: "plane/one",
    };
    let mut out = Reply::new();
    write_echo(&mut out, echo).unwrap();
    assert_eq!(decode_echo(out.as_bytes()).unwrap(), echo);
    write_echo(&mut out, echo).unwrap();
    assert!(
        decode_echo(out.as_bytes()).is_err(),
        "two echoes cannot select authority by order"
    );
}

#[test]
fn selection_answer_is_bounded_before_decoding() {
    assert!(decode_selection(&vec![0; 16 * 1024 + 1]).is_err());
    let mut out = Reply::new();
    for n in 0..33 {
        write_selection(
            &mut out,
            &[Scope {
                kind: "pool",
                value: &format!("r{n}"),
            }],
        )
        .unwrap();
    }
    assert!(decode_selection(out.as_bytes()).is_err());
}
