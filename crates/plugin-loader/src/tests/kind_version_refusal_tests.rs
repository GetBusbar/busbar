// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **NO LEGACY LOADING, KIND BY KIND** (THE DESIGN §11.8, Appendix A.9; TODO ABI-b6). The one loader
//! accepts only the current version of each kind and refuses older and newer alike, naming the kind,
//! both versions and the rebuild against the 1.6.0 SDK; a 1.5.5 JSON-contract plugin is refused as
//! one. Every kind but hook is driven here (the hook kind's 1.5.5 refusal is WIRE-HOOK's):
//!
//! * a door of the kind at the host's kind ABI ± 1 is refused by the one validator both origins run
//!   (`validate_door`), and the same door at the host's version gets past the version check;
//! * a dropped-in plugin whose signed manifest states the kind at ± 1 is refused before `dlopen`;
//! * the `json_contract_1_5_5` example cdylib — the 1.5.5 entry `busbar_abi` and no door — dropped
//!   in as the kind is refused as a 1.5.5 JSON-contract plugin, naming the rebuild.

use std::path::Path;
use std::sync::Arc;

use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC;
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};

use crate::dispatch::kinds::{
    auth::Auth, export::Export, plane::Plane, secret::Secret, store::Store, transport::Transport,
};
use crate::dispatch::load::validate_door;
use crate::dispatch::{load_dropped, DispatchConfig, Dispatcher, Kind, LoadError};

const REBUILD: &str = "rebuild the plugin against the 1.6.0 SDK";

/// A door of `K` at `kind_abi`, everything past the version check NULL.
fn door<K: Kind>(kind_abi: u32) -> Door {
    Door {
        magic: DOOR_MAGIC,
        mechanism_version: MECHANISM_VERSION,
        size: std::mem::size_of::<Door>() as u32,
        kind: K::CODE as u32,
        kind_abi,
        statement: std::ptr::null(),
        ops: std::ptr::null(),
    }
}

/// The head of a Statement rendering stating `K` at `kind_abi` (what a signed manifest carries).
fn stated<K: Kind>(kind_abi: u32) -> Vec<u8> {
    let mut r = RENDERING_MAGIC.to_vec();
    for word in [MECHANISM_VERSION, K::CODE as u32, kind_abi] {
        r.extend_from_slice(&word.to_le_bytes());
    }
    r
}

fn dropped<K: Kind>(path: &Path, stated: &[u8]) -> Option<LoadError> {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    load_dropped::<K>(path, stated, crate::door_both_ways::bind(&d)).err()
}

fn names_both_versions(e: &LoadError, kind: KindCode, theirs: u32, host: u32) {
    let text = e.to_string();
    for want in [
        format!("{kind:?}"),
        theirs.to_string(),
        host.to_string(),
        REBUILD.to_string(),
    ] {
        assert!(
            text.contains(&want),
            "{kind:?}: the refusal names `{want}`: {text}"
        );
    }
}

/// `K`'s door and manifest at the host's kind ABI ± 1 are each refused, naming the kind, both
/// versions and the rebuild; the door at the host's version passes the version check.
fn refuses_another_kind_abi<K: Kind>() {
    let (kind, host) = (K::CODE, K::CODE.abi_version());
    assert_eq!(
        validate_door::<K>(&door::<K>(host)).err(),
        Some(LoadError::NullOps),
        "{kind:?}: the door at the host's version gets past the version check"
    );
    let nowhere = Path::new("/nonexistent/libnothing.so");
    for theirs in [host - 1, host + 1] {
        let want = LoadError::KindAbi {
            kind,
            door: theirs,
            host,
        };
        assert_eq!(
            validate_door::<K>(&door::<K>(theirs)).err(),
            Some(want.clone())
        );
        names_both_versions(&want, kind, theirs, host);

        let refused = dropped::<K>(nowhere, &stated::<K>(theirs));
        let want = LoadError::ManifestKindAbi {
            kind,
            stated: theirs,
            host,
        };
        assert_eq!(
            refused,
            Some(want.clone()),
            "{kind:?}: refused before dlopen"
        );
        names_both_versions(&want, kind, theirs, host);
    }
}

#[test]
fn a_store_door_at_another_kind_abi_is_refused() {
    refuses_another_kind_abi::<Store>();
}

#[test]
fn a_secret_door_at_another_kind_abi_is_refused() {
    refuses_another_kind_abi::<Secret>();
}

#[test]
fn an_auth_door_at_another_kind_abi_is_refused() {
    refuses_another_kind_abi::<Auth>();
}

#[test]
fn an_export_door_at_another_kind_abi_is_refused() {
    refuses_another_kind_abi::<Export>();
}

#[test]
fn a_plane_door_at_another_kind_abi_is_refused() {
    refuses_another_kind_abi::<Plane>();
}

#[test]
fn a_transport_door_at_another_kind_abi_is_refused() {
    refuses_another_kind_abi::<Transport>();
}

/// The 1.5.5 JSON-contract cdylib, dropped in as `K` under a manifest stating `K`'s current
/// version, is refused as a 1.5.5 JSON-contract plugin naming the rebuild — never as a library that
/// merely lacks a door.
fn refuses_the_1_5_5_json_contract_plugin<K: Kind>(path: &Path) {
    let (kind, host) = (K::CODE, K::CODE.abi_version());
    let refused = dropped::<K>(path, &stated::<K>(host));
    assert_eq!(refused, Some(LoadError::JsonContract { kind }));
    let text = refused.map(|e| e.to_string()).unwrap_or_default();
    for want in [
        "1.5.5 JSON-contract".to_string(),
        format!("{kind:?}"),
        "busbar_abi".to_string(),
        format!("mechanism version {}", MECHANISM_VERSION - 1),
        format!("mechanism version {MECHANISM_VERSION}"),
        format!("{kind:?} ABI version {host}"),
        REBUILD.to_string(),
    ] {
        assert!(
            text.contains(&want),
            "{kind:?}: the refusal names `{want}`: {text}"
        );
    }
}

/// RED on a loader that reads a door-less library only as `NoDoor`.
#[test]
fn a_1_5_5_json_contract_plugin_is_refused_as_one_naming_the_rebuild() {
    let Some(path) = crate::both_ways::example_cdylib("json_contract_1_5_5") else {
        eprintln!("skip: the json_contract_1_5_5 example cdylib is not built (outside CI)");
        return;
    };
    refuses_the_1_5_5_json_contract_plugin::<Store>(&path);
    refuses_the_1_5_5_json_contract_plugin::<Secret>(&path);
    refuses_the_1_5_5_json_contract_plugin::<Auth>(&path);
    refuses_the_1_5_5_json_contract_plugin::<Export>(&path);
    refuses_the_1_5_5_json_contract_plugin::<Plane>(&path);
    refuses_the_1_5_5_json_contract_plugin::<Transport>(&path);
}
