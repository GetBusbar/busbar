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

    /// A minimal Statement rendering (secret kind, no lists, no blobs) stamped `mechanism`.
    fn rendering(mechanism: u32) -> Vec<u8> {
        let mut b = busbar_artifact_metadata::rendering::RENDERING_MAGIC.to_vec();
        let u32s = |b: &mut Vec<u8>, words: &[u32]| {
            for w in words {
                b.extend_from_slice(&w.to_le_bytes());
            }
        };
        let s = |b: &mut Vec<u8>, text: &str| {
            b.extend_from_slice(&u32::try_from(text.len()).unwrap().to_le_bytes());
            b.extend_from_slice(text.as_bytes());
        };
        // mechanism, kind, kind_abi, max_inflight
        u32s(
            &mut b,
            &[mechanism, KindCode::Secret as u32, abi_of(KindCode::Secret), 1],
        );
        s(&mut b, "the-plugin");
        s(&mut b, "1.0.0");
        // families, diag_ids, kind_tail size, kind_tail_facts length
        u32s(&mut b, &[0, 0, 0, 0]);
        // extensions blob, secret_refs, settings_schema blob
        u32s(&mut b, &[0, 0, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&0u64.to_le_bytes()); // marks
        // mark_words, rewrites, sections, needs
        u32s(&mut b, &[0, 0, 0, 0]);
        s(&mut b, ""); // target_from
        s(&mut b, ""); // trust_from
        // answers, claims, measurement_classes
        u32s(&mut b, &[0, 0, 0]);
        b
    }

    /// ABI-MECH: the mechanism a Statement rendering is stamped with is busbar-plugin-abi's
    /// `versions::CORE` (the number `ci/abi.pin` pins and the loader admits a native stamp at), and
    /// only that exact number reads back: the previous generation and the next are refused.
    #[test]
    fn a_statement_stamped_with_another_mechanism_is_refused_and_core_is_admitted() {
        use busbar_plugin_abi::versions::CORE;
        let stamped = |mechanism: u32| Manifest {
            kind: "secret".to_string(),
            abi_version: abi_of(KindCode::Secret),
            statement: Some(hex::encode(rendering(mechanism))),
            ..Manifest::default()
        };
        let admitted = stamped(CORE).stated();
        assert!(
            admitted
                .as_ref()
                .is_ok_and(|s| s.as_ref().is_some_and(|s| s.mechanism_version == CORE)),
            "{admitted:?}"
        );
        for wrong in [CORE - 1, CORE + 1] {
            let refused = stamped(wrong).stated();
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|why| why.contains("the current mechanism version")),
                "mechanism {wrong}: {refused:?}"
            );
        }
    }
}
