// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verify step's guards have one home, and it is not this crate.
//!
//! The pool allow-list, the fallback walk and the unpriced-destination gate that refuse a unit before
//! it is charged are the kernel door's. A second copy here, with its own seal rule, its own ordering
//! and its own weighted selector, ran in no shipped path: its tests proved a rule the node never
//! applied, and the copy had already drifted from the one that refuses real requests (it asked a
//! billing question the door deliberately does not). A capability that is never constructed does not
//! ship, so the copy is gone, and this test keeps it gone.
//!
//! What stays under `trust` is the network readers the connector and the kernel call: `net`.

use std::path::Path;

/// The modules the trust tree may hold: the network readers, and the module root that names them.
const ALLOWED: &[&str] = &["mod.rs", "net.rs"];

#[test]
fn the_trust_tree_holds_the_network_readers_and_no_second_verify_step() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/trust");
    let mut strays: Vec<String> = std::fs::read_dir(&dir)
        .expect("the trust module is readable")
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    strays.sort();
    assert!(
        strays.is_empty(),
        "the trust tree carries modules no shipped path constructs (a second verify step, \
         ordering, lane model or selector beside the kernel door's): {strays:?}"
    );
}

#[test]
fn no_verify_unit_is_exported() {
    let root =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/trust/mod.rs"))
            .expect("the trust module root is readable");
    for item in [
        "pub mod unit",
        "pub mod guard",
        "pub mod destination",
        "pub mod lane",
        "pub mod order",
        "pub mod swrr",
        "pub mod counterparty",
        "pub mod arity",
    ] {
        assert!(
            !root.contains(item),
            "the trust module still declares `{item}`, which no shipped path constructs"
        );
    }
}

/// THE ONE DESTINATION JUDGE IS THE CONNECTOR'S (row 159, kernel-egress round 3 MEDIUM): `trust::net`
/// declares no second address guard. The policy, the resolve-then-pin, the dial-time denylist and
/// table and the sealed-destination check it once carried ran in no dial path (every dial is judged
/// by `busbar-core-connector`'s `guard`, the one `dest.judge`), while its prose said the connector
/// and the kernel called it. RED while any of them is declared; its GREEN twin is
/// [`the_network_readers_live_code_calls_stay`].
#[test]
fn trust_net_declares_no_second_destination_judge() {
    let net =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/trust/net.rs"))
            .expect("the network readers are readable");
    let declared: Vec<&str> = [
        "pub struct GuardPolicy",
        "pub struct PinnedTarget",
        "pub fn judge_host_name",
        "pub fn judge_address",
        "pub fn pin_answer",
        "pub fn resolve_and_pin",
        "pub struct Denylist",
        "pub struct DialDenylist",
        "pub struct DialTable",
        "pub enum NetworkRefusal",
        "pub fn check_destination",
        "pub fn check_structure",
    ]
    .into_iter()
    .filter(|item| net.contains(item))
    .collect();
    assert!(
        declared.is_empty(),
        "trust::net declares a second destination judge beside the connector's: {declared:?}"
    );
}

/// GREEN twin of [`trust_net_declares_no_second_destination_judge`]: the readers live code calls
/// stay, and still answer. The connector reads `split_url` and implements `Resolver`; config
/// validation reads `ssrf_blocked_host` (over the contract's `METADATA_HOSTS`); every place that
/// carries a configured URL reads `strip_userinfo` or `redact_userinfo`.
#[test]
fn the_network_readers_live_code_calls_stay() {
    use busbar_kernel_egress::trust::net::{
        redact_userinfo, split_url, ssrf_blocked_host, strip_userinfo, AddressRefusal, Resolver,
        METADATA_HOSTS,
    };

    struct NoNames;
    impl Resolver for NoNames {
        fn resolve(&self, _host: &str) -> Result<Vec<std::net::IpAddr>, String> {
            Err("no names".into())
        }
    }
    assert!(NoNames.resolve("a.example").is_err());

    let (https, host, port, _) = split_url("https://api.example.com/v1").expect("an https URL");
    assert!(https);
    assert_eq!((host.as_str(), port), ("api.example.com", 443));
    assert!(matches!(
        split_url("file:///etc/passwd"),
        Err(AddressRefusal::Scheme { .. })
    ));

    for name in METADATA_HOSTS {
        assert!(
            ssrf_blocked_host(&format!("https://{name}/"), &[], false, &[]).is_some(),
            "`{name}` is on the metadata list and the config arm let it through"
        );
    }
    assert!(ssrf_blocked_host("https://api.example.com/v1", &[], false, &[]).is_none());

    assert_eq!(
        strip_userinfo("https://u:p@api.example.com/v1"),
        "https://api.example.com/v1"
    );
    assert!(!redact_userinfo("https://u:secret@api.example.com/v1").contains("secret"));
}
