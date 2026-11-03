// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use crate::both_ways::{dropped, statement};
use crate::dispatch::kinds::transport::TransportFacts;
use crate::dispatch::{in_head, out_head, Adopter, Bind, Frame, NoSink};
use crate::sign::validate_structure;
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::ROLE_CARRIER;

fn fixture() -> Vec<u8> {
    std::fs::read(fixture_path()).expect("read the cdylib")
}

fn fixture_path() -> std::path::PathBuf {
    let p = std::env::var_os("BUSBAR_TEST_TCP_CDYLIB")
        .map(std::path::PathBuf::from)
        .expect("BUSBAR_TEST_TCP_CDYLIB names the qualified actual TCP product");
    assert!(
        crate::dispatch::rendering_of_library(&p)
            .ok()
            .flatten()
            .and_then(|stated| {
                crate::dispatch::load_dropped::<crate::dispatch::kinds::transport::Transport>(
                    &p,
                    &stated,
                    bind(),
                )
                .ok()
            })
            .and_then(|d| d.context::<TransportFacts>().cloned())
            .is_some_and(|f| f.role == ROLE_CARRIER && f.claims == ["tcp"]),
        "the actual TCP product admits as the carrier claiming tcp"
    );
    p
}

fn bind() -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    }
}

fn log_config() -> crate::dispatch::PluginLogConfig {
    static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    let dir = DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "busbar-transport-plugin-log-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    });
    crate::dispatch::PluginLogConfig::from_words(
        Some(dir.to_str().expect("a UTF-8 scratch path")),
        None,
        &Default::default(),
        None,
        None,
    )
    .expect("the named directory resolves")
}

fn manifest() -> crate::sign::Manifest {
    let rendering = crate::dispatch::rendering_of_library(&fixture_path())
        .expect("the actual TCP image renders")
        .expect("the actual TCP image exports its door");
    let read = busbar_contract::abi::mechanism::rendering::read(&rendering)
        .expect("the actual TCP statement reads");
    let declares = busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes)
        .map(crate::sign::Declares::from_declares_json)
        .transpose()
        .expect("the actual TCP declares document reads")
        .unwrap_or_default();
    crate::sign::Manifest {
        version: read.version,
        statement: Some(hex::encode(rendering)),
        declares,
        ..statement(
            busbar_contract::abi::mechanism::kind::TRANSPORT,
            &read.name,
            "tcp",
            busbar_contract::abi::transport::ABI_VERSION,
        )
    }
}

fn packed() -> crate::sign::Manifest {
    crate::sign::Manifest {
        sha256: crate::sign::sha256_hex(b"lib"),
        ..manifest()
    }
}

#[test]
fn a_signed_door_tarball_is_opened_through_the_one_door() {
    let lib = fixture();
    let registry = dropped("door-fixture", manifest(), &lib);
    let entries = registry
        .open_transport_entries(&bind(), &uses(&["tcp"]), &log_config())
        .expect("the door opens");
    assert_eq!(entries.doors.len(), 1);
    let door = &entries.doors[0];
    let facts = door.context::<TransportFacts>().expect("its tail");
    assert_eq!(
        facts.role, ROLE_CARRIER,
        "the actual TCP door is the carrier, never a framer"
    );
    assert_eq!(facts.claims, ["tcp"], "the actual carrier claims tcp");
    assert!(
        facts.composes_over.is_empty(),
        "the actual TCP carrier does not compose over another carrier"
    );
    let mut i: OpenIn = blank_in();
    i.head = in_head();
    i.settings = Blob {
        ptr: b"{}".as_ptr(),
        len: 2,
        fmt: BLOB_JSON,
        flags: 0,
    };
    let mut o: OpenOut = blank_out();
    o.head = out_head();
    assert_eq!(
        door.call(life::OPEN, &mut Frame::new(i, o)).outcome,
        Outcome::Ready
    );
}

#[test]
fn a_manifest_outside_the_transport_version_window_is_refused() {
    validate_structure(&packed(), b"lib", &crate::supported_abi, "")
        .expect("a transport is a kind the loader admits");
    let mut old = packed();
    old.abi_version = busbar_contract::abi::transport::ABI_VERSION - 1;
    assert!(validate_structure(&old, b"lib", &crate::supported_abi, "").is_err());
    let mut newer = packed();
    newer.abi_version = busbar_contract::abi::transport::ABI_VERSION + 1;
    assert!(validate_structure(&newer, b"lib", &crate::supported_abi, "").is_err());
}

#[test]
fn a_transport_library_with_no_door_is_refused() {
    let lib = std::fs::read(crate::both_ways::example_cdylib("json_contract_auth"))
        .expect("read the cdylib");
    let manifest = statement(
        busbar_contract::abi::mechanism::kind::TRANSPORT,
        "no-door",
        "no-door",
        busbar_contract::abi::transport::ABI_VERSION,
    );
    let registry = dropped("no-door", manifest, &lib);
    let why = registry
        .open_transport_entries(&bind(), &uses(&["no-door"]), &log_config())
        .err()
        .expect("a library with no door is not a transport");
    assert!(
        why.contains("exports no memory-ABI door"),
        "the refusal names the missing door: {why}"
    );
}

fn uses(schemes: &[&str]) -> crate::boot::Uses {
    crate::boot::Uses {
        schemes: schemes.iter().map(|s| (*s).to_string()).collect(),
        ..crate::boot::Uses::default()
    }
}

#[test]
fn a_dropped_transport_no_configured_scheme_selects_is_never_opened() {
    let lib = fixture();
    let registry = dropped("door-fixture", manifest(), &lib);
    let entries = registry
        .open_transport_entries(&bind(), &uses(&["https"]), &log_config())
        .expect("nothing to open is no refusal");
    assert!(
        entries.doors.is_empty(),
        "a transport whose claims no configured scheme uses was opened: {:?}",
        entries.doors.iter().map(|d| d.name()).collect::<Vec<_>>()
    );
    let entries = registry
        .open_transport_entries(&bind(), &uses(&["tcp"]), &log_config())
        .expect("the selected door opens");
    assert_eq!(entries.doors.len(), 1, "the scheme it claims selects it");
}

#[test]
fn a_dropped_transport_is_bound_to_its_own_plugin_log_file() {
    let lib = fixture();
    let registry = dropped("door-fixture", manifest(), &lib);
    let logs = log_config();
    let entries = registry
        .open_transport_entries(&bind(), &uses(&["tcp"]), &logs)
        .expect("the door opens");
    assert_eq!(entries.doors.len(), 1);
    let path = logs.path_for(
        &manifest().name,
        busbar_contract::abi::mechanism::KindCode::Transport,
    );
    assert!(
        path.is_file(),
        "the transport instance's plugin log file {} was not opened at its bind",
        path.display()
    );
}

#[path = "transport_receive_tests.rs"]
mod receive_tests;
