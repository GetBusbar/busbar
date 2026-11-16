// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The frozen surface of the MIN-3 interface (ABI-MIN3-INTERFACE round 34) is present under its frozen paths and
//! its wire numbers keep their frozen values. Wave 0 (W0-ABI) lands the items as stubs; a wave-1 task that moves,
//! renames or renumbers one fails here. The numbers are the IF's; the type list names one item per frozen file.

use busbar_plugin_abi as abi;

/// Frozen paths still defined in this crate.
#[test]
fn the_frozen_types_exist_under_their_frozen_paths() {
    let names = [
        core::any::type_name::<abi::records::RecHead>(),
        core::any::type_name::<abi::records::EndpointRec>(),
        core::any::type_name::<abi::records::FailRec>(),
        core::any::type_name::<abi::records::Records<'static>>(),
        core::any::type_name::<abi::records::Out<'static>>(),
        core::any::type_name::<abi::records::Reply>(),
        core::any::type_name::<abi::fail::Fail>(),
        core::any::type_name::<abi::plugin::Endpoints<'static>>(),
        core::any::type_name::<abi::plugin::Describe<'static>>(),
        core::any::type_name::<abi::stamp::Stamp>(),
        core::any::type_name::<abi::versions::EngineVersion>(),
        core::any::type_name::<abi::export::CustodyRec>(),
        core::any::type_name::<abi::export::DeliveryRec>(),
    ];
    assert!(
        names
            .iter()
            .all(|name| name.starts_with("busbar_plugin_abi::"))
    );
}

/// Frozen paths that busbar-ffi now defines (UNSAFE-MIN r3.1) and this crate re-exports: each resolves under its
/// frozen path, and the type behind it is busbar-ffi's, so there is one definition on both sides of the boundary.
#[test]
fn the_boundary_types_resolve_under_their_frozen_paths_to_busbar_ffi() {
    let names = [
        core::any::type_name::<abi::types::Bytes<'static>>(),
        core::any::type_name::<abi::types::Str<'static>>(),
        core::any::type_name::<abi::types::Slice<'static, abi::types::Pair<'static>>>(),
        core::any::type_name::<abi::types::RawOut>(),
        core::any::type_name::<abi::types::Status>(),
        core::any::type_name::<abi::types::KindCode>(),
        core::any::type_name::<abi::plugin::Plugin>(),
        core::any::type_name::<abi::need::ChainBytes>(),
        core::any::type_name::<abi::host::Host>(),
        core::any::type_name::<abi::host::DeploymentId>(),
    ];
    assert!(names.iter().all(|name| name.starts_with("busbar_ffi::")));
}

#[test]
fn the_kind_numbers_and_abi_versions_are_frozen() {
    let kinds = [
        (abi::types::KindCode::Store, 1, "store", 3),
        (abi::types::KindCode::Secret, 2, "secret", 2),
        (abi::types::KindCode::Auth, 3, "auth", 3),
        (abi::types::KindCode::Hook, 4, "hook", 2),
        (abi::types::KindCode::Export, 5, "export", 3),
        (abi::types::KindCode::Plane, 6, "plane", 1),
        (abi::types::KindCode::Transport, 7, "transport", 1),
    ];
    for (kind, raw, word, version) in kinds {
        assert_eq!(kind as u32, raw);
        assert_eq!(abi::types::KindCode::from_raw(raw), Some(kind));
        assert_eq!(kind.word(), word);
        assert_eq!(abi::versions::abi_of(kind), version);
    }
    assert_eq!(abi::types::KindCode::from_raw(0), None);
    assert_eq!(abi::types::KindCode::from_raw(8), None);
    let modules = [
        (abi::store::KIND, abi::store::ABI),
        (abi::secret::KIND, abi::secret::ABI),
        (abi::auth::KIND, abi::auth::ABI),
        (abi::hook::KIND, abi::hook::ABI),
        (abi::export::KIND, abi::export::ABI),
        (abi::plane::KIND, abi::plane::ABI),
        (abi::transport::KIND, abi::transport::ABI),
    ];
    for (kind, version) in modules {
        assert_eq!(abi::versions::abi_of(kind), version);
    }
}

#[test]
fn the_wire_numbers_are_frozen() {
    assert_eq!(
        [
            abi::types::Status::OK,
            abi::types::Status::REFUSED,
            abi::types::Status::FAILED,
            abi::types::Status::NEED,
            abi::types::Status::FAULT,
        ]
        .map(|status| status.0),
        [0, 1, 2, 3, 4]
    );
    assert_eq!(abi::types::TOKEN_SESSION, 1 << 63);
    // Generic records (§3), incl. round 32's ENDPOINT and round 34's ERROR / D_ERRORS.
    assert_eq!(
        [
            abi::records::tag::FAIL,
            abi::records::tag::TOKEN,
            abi::records::tag::CONFIG,
            abi::records::tag::ERROR,
            abi::records::tag::D_ERRORS,
            abi::records::tag::ENDPOINT,
        ],
        [0x0002, 0x0003, 0x000B, 0x000D, 0x004C, 0x0075]
    );
    assert_eq!(abi::fail::refused::R_VERSION, 17);
    assert_eq!(abi::plugin::OPEN_DRY_RUN, 1);
    // The export kind as frozen at round 33 (§49).
    assert_eq!(abi::export::tag::CUSTODY, 0x0104);
    assert_eq!(abi::export::tag::D_DELIVERY, 0x0183);
    assert_eq!(
        [
            abi::export::CUSTODY_NONE,
            abi::export::CUSTODY_ACCEPTED,
            abi::export::CUSTODY_DURABLE,
            abi::export::CUSTODY_INDEXED,
        ],
        [0, 1, 2, 3]
    );
    assert_eq!(
        (abi::export::STREAM_CONTENT, abi::export::STREAM_COUNT),
        (9, 10)
    );
    assert_eq!(
        [
            abi::export::M_DELIVER,
            abi::export::M_RENDER,
            abi::export::M_CONFIRM,
        ],
        [1, 2, 4]
    );
}
