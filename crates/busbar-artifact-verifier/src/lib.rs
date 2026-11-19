// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read-only artifact verification. Publisher trust does not qualify a cryptographic provider.
#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]
/// The same shared JSON facade used by release documents and manifest serialization.
pub use busbar_json as json;
pub mod refusal;
pub mod release_trust;
pub mod scan;
pub mod sign;
pub mod tarball;
pub mod verification;
use busbar_plugin_abi::types::KindCode;
/// The existing source-current rebuild remedy.
pub const REBUILD: &str = "rebuild the plugin against the 1.6.0 SDK";

/// The manifest word for a kind (`sign::KNOWN_KINDS`).
pub fn kind_word(kind: KindCode) -> &'static str {
    match kind {
        KindCode::Store => "store",
        KindCode::Secret => "secret",
        KindCode::Auth => "auth",
        KindCode::Hook => "hook",
        KindCode::Export => "export",
        KindCode::Plane => "plane",
        KindCode::Transport => "transport",
    }
}

/// The ONE abi_version this binary loads for `kind` (LINT-RULES R21: exact match, never a range
/// or a set); `None` for a kind it does not know. The number is busbar-plugin-abi's
/// `versions::abi_of`, the same one a native stamp must carry (`sign::validate_native_manifest`).
pub fn supported_abi(kind: &str) -> Option<u32> {
    (1..=7)
        .filter_map(KindCode::from_raw)
        .find(|&code| kind_word(code) == kind)
        .map(busbar_plugin_abi::versions::abi_of)
}

#[cfg(test)]
mod abi_tests {
    use super::{kind_word, supported_abi};
    use crate::sign::{validate_abi, Manifest};
    use busbar_plugin_abi::types::KindCode;
    use busbar_plugin_abi::versions::abi_of;

    #[test]
    fn supported_abi_is_the_call_shape_number_of_every_kind() {
        for code in (1..=7).filter_map(KindCode::from_raw) {
            assert_eq!(
                supported_abi(kind_word(code)),
                Some(abi_of(code)),
                "{}",
                kind_word(code)
            );
        }
        assert_eq!(supported_abi("mechanism"), None);
    }

    #[test]
    fn an_artifact_stamped_with_the_old_store_number_3_is_refused() {
        let old = Manifest {
            kind: "store".to_string(),
            abi_version: 3,
            ..Manifest::default()
        };
        let refused = validate_abi(&old, &supported_abi);
        assert!(
            refused
                .as_ref()
                .is_err_and(|why| why.contains("abi_version 3 is not supported")),
            "{refused:?}"
        );
        let current = Manifest {
            abi_version: abi_of(KindCode::Store),
            ..old
        };
        assert_eq!(validate_abi(&current, &supported_abi), Ok(()));
    }
}
