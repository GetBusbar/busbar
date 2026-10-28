// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DROPPED-IN TRANSPORT DOOR THROUGH THE REGISTRY: the neutral frame door's `cdylib`, signed
//! first-party into a `plugins/` directory, is scanned, trusted, staged, `dlopen`ed once and
//! admitted through the one dispatcher's door validation — its tail read into the claims the
//! connector's registry view serves. A manifest outside the transport's version window is refused
//! at the structural gate, and a library with no door is refused outright: the HOT transport lane
//! is deleted, so a door is the only way a transport loads.

use std::sync::Arc;

use crate::both_ways::{dropped, statement};
use crate::dispatch::kinds::transport::TransportFacts;
use crate::dispatch::{in_head, out_head, Adopter, Bind, Frame, NoSink};
use crate::sign::validate_structure;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::ROLE_FRAMER;

/// The neutral frame door (`tests/fixtures/neutral_frame_door.rs`): a dropped-in transport door
/// that frames the host's socket, built beside the test binary as this crate's example `cdylib`.
/// A missing artifact is a failure naming the command that builds it, never a skip.
fn fixture() -> Vec<u8> {
    std::fs::read(fixture_path()).expect("read the cdylib")
}

/// Where [`fixture`] is: the neutral frame door example, which admits against its own Statement
/// rendering as a transport composing over nothing.
fn fixture_path() -> std::path::PathBuf {
    let p = crate::both_ways::example_cdylib("neutral_frame_door");
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
            .is_some_and(|f| f.composes_over.is_empty()),
        "the neutral frame door example admits as a transport composing over nothing"
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

/// A plugin log directory of this test binary's own, named (`plugins.logs.dir`), so every sink
/// bound under it opens its file as it is bound.
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

/// The fixture's manifest, stating the door's Statement rendering as its signed manifest does (the
/// door is admitted against it).
fn manifest() -> crate::sign::Manifest {
    let rendering = crate::dispatch::rendering_of_library(&fixture_path())
        .ok()
        .flatten();
    crate::sign::Manifest {
        statement: rendering.map(hex::encode),
        ..statement(
            busbar_contract::abi::mechanism::kind::TRANSPORT,
            "door-fixture",
            "door-fixture",
            busbar_contract::abi::transport::ABI_VERSION,
        )
    }
}

/// The manifest as the structural gate reads a packed one: an artifact digest present.
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
        .open_transport_entries(&bind(), &uses(&["door-fixture"]), &log_config())
        .expect("the door opens");
    assert_eq!(entries.doors.len(), 1);
    let door = &entries.doors[0];
    let facts = door.context::<TransportFacts>().expect("its tail");
    assert_eq!(
        facts.role, ROLE_FRAMER,
        "the neutral door frames a byte stream; it is never a carrier"
    );
    assert_eq!(facts.claims, [door.name()], "one claim: its own");
    assert!(
        facts.composes_over.is_empty(),
        "it frames whatever carrier the connector rides"
    );
    let mut i: OpenIn = blank_in();
    i.head = in_head();
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

/// RED: a transport library with no memory-ABI door is refused, naming the door, rather than read
/// over another lane. The 1.5.5-shaped library exports the frozen handshake and no
/// `busbar_plugin_door`, which is what a HOT-lane transport image was.
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

/// A configuration that uses the URL schemes `schemes` and nothing else.
fn uses(schemes: &[&str]) -> crate::boot::Uses {
    crate::boot::Uses {
        schemes: schemes.iter().map(|s| (*s).to_string()).collect(),
        ..crate::boot::Uses::default()
    }
}

/// LAW 7 FOR A DROPPED-IN TRANSPORT (`BUSBAR-1.6.0.md` l.1908-1910: "Core loads a plugin **iff** its
/// configuration section is present. No verb configured → that plugin is never loaded."; l.351:
/// "Select picks a dropped-in transport from the signed manifest without opening it").
///
/// RED before the registry opened only the transports a configured URL's scheme selects: every
/// admitted `kind: transport` image was staged, loaded and opened, whatever the configuration
/// dialled, so its library initialisers ran in a node that never named its scheme.
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
        .open_transport_entries(&bind(), &uses(&["door-fixture"]), &log_config())
        .expect("the selected door opens");
    assert_eq!(entries.doors.len(), 1, "the scheme it claims selects it");
}

/// A DROPPED-IN TRANSPORT WRITES ITS OWN PLUGIN LOG (`BUSBAR-1.6.0.md` THE DESIGN §11.2, "Plugin
/// logging": "all plugins should log to their plugin's log file. no logs for plugins is not an
/// option ... The HOST writes it to that plugin instance's own log file").
///
/// RED before an opened transport door was bound to its instance's log file: every dropped-in
/// transport took the bind's sink (the root's `NoSink`), so what it logged went nowhere and no
/// transport plugin log file was ever opened.
#[test]
fn a_dropped_transport_is_bound_to_its_own_plugin_log_file() {
    let lib = fixture();
    let registry = dropped("door-fixture", manifest(), &lib);
    let logs = log_config();
    let entries = registry
        .open_transport_entries(&bind(), &uses(&["door-fixture"]), &logs)
        .expect("the door opens");
    assert_eq!(entries.doors.len(), 1);
    let path = logs.path_for(
        "door-fixture",
        busbar_contract::abi::mechanism::KindCode::Transport,
    );
    assert!(
        path.is_file(),
        "the transport instance's plugin log file {} was not opened at its bind",
        path.display()
    );
}
