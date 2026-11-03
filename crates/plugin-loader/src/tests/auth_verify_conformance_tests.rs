// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::both_ways::{dropped_third_party, row};
use crate::{LinkedPlugin, PluginRegistry};

// The former scripted auth-verify fixture's real verdict/origin properties live in
// kernel_application/auth_verify_both_origins.rs. Its short-reply ownership properties
// live in ordinary_auth_short.rs over the actual SDK. Keep this distinct registry
// publisher-origin control against the qualified OIDC image here.

// The real OIDC image is held while its immutable SDK descriptor is lent to the registry.
fn actual_oidc() -> (
    std::path::PathBuf,
    busbar_contract::abi::mechanism::door::DoorFn,
) {
    use busbar_contract::abi::sdk::door::RawDoorFn;
    use std::sync::OnceLock;
    static IMAGE: OnceLock<(std::path::PathBuf, libloading::Library, RawDoorFn)> = OnceLock::new();
    extern "C" fn door() -> &'static busbar_contract::abi::mechanism::door::Door {
        let image = IMAGE.get_or_init(|| {
            let path = std::env::var_os("BUSBAR_AUTH_TEST_OIDC_PLUGIN")
                .map(std::path::PathBuf::from)
                .expect("BUSBAR_AUTH_TEST_OIDC_PLUGIN names the actual qualified OIDC image");
            assert!(path.is_absolute() && path.is_file());
            let library = crate::dlopen_on_worker(path.as_os_str())
                .expect("actual OIDC loads on the plugin worker");
            // SAFETY: the exact product image exports the typed SDK door entry and remains in IMAGE.
            let entry = unsafe {
                *library
                    .get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                    .expect("actual OIDC door")
            };
            (path, library, entry)
        });
        let raw = crate::dispatch::load::enter_door(image.2);
        crate::dispatch::load::validate_door::<crate::dispatch::kinds::auth::Auth>(raw)
            .expect("actual OIDC auth descriptor validates");
        // SAFETY: validation establishes the descriptor; IMAGE holds its mapping for every loan.
        unsafe { &*raw }
    }
    let _ = door();
    (IMAGE.get().unwrap().0.clone(), door)
}

#[test]
fn a_third_party_signature_is_a_different_row() {
    let (path, door) = actual_oidc();
    let image = std::fs::read(path).expect("read the actual OIDC image");
    let stated = crate::dispatch::rendering_of(door).expect("actual OIDC statement renders");
    let module = busbar_contract::abi::mechanism::rendering::read(&stated)
        .expect("actual OIDC statement reads")
        .name;
    let manifest = LinkedPlugin::first_party_door("auth", &module, "the-auth", door).manifest;
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(manifest.clone(), door)])
        .expect("actual OIDC linked row");
    let mut third_party = manifest;
    third_party.publisher = "a-third-party".into();
    let dropped = dropped_third_party("actual-oidc", third_party, &image);
    let dropped_row = row(&dropped, &module);
    assert!(!dropped_row.starts_with("no row"), "{dropped_row}");
    assert_ne!(
        row(&linked, &module),
        dropped_row,
        "a third-party actual OIDC row must not compare equal to the first-party one"
    );
}
