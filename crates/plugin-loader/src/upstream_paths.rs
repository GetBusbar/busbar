// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(test)]
mod tests {
    use busbar_plugin_abi::records::{tag, MaskRec, Records, Reply};
    use busbar_plugin_abi::types::KindCode;

    fn decode(
        kind: KindCode,
        paths: &[(u16, &str)],
    ) -> Result<crate::instance::Described, crate::refusal::Refusal> {
        let mut frame = Reply::new();
        frame
            .put_pod(
                tag::D_METHODS,
                &MaskRec {
                    mask: match kind {
                        KindCode::Plane => busbar_plugin_abi::kinds::plane::plane::REQUIRED,
                        _ => busbar_plugin_abi::kinds::store::store::REQUIRED,
                    },
                },
            )
            .unwrap();
        for (tag, path) in paths {
            frame.put_text(*tag, path).unwrap();
        }
        crate::chains::decode_described(kind, Records::new(frame.as_bytes()))
    }

    #[test]
    fn upstream_declarations_refuse_invalid_syntax_kind_count_and_overlap() {
        for path in [
            "",
            "servers/*",
            "/servers",
            "/servers/*/nested",
            "/s~2/*",
            "/s~/*",
            "/s/*/*",
        ] {
            assert!(
                decode(KindCode::Plane, &[(0x004D, path)]).is_err(),
                "{path}"
            );
        }
        assert!(decode(KindCode::Store, &[(0x004D, "/*")]).is_err());
        assert!(decode(
            KindCode::Plane,
            &[
                (0x004D, "/a/*"),
                (0x004D, "/b/*"),
                (0x004D, "/c/*"),
                (0x004D, "/d/*"),
                (0x004D, "/e/*")
            ]
        )
        .is_err());
        for other in ["/a/*", "/a/*/nested/*", "/a/specific/nested/*"] {
            assert!(decode(KindCode::Plane, &[(0x004D, "/a/*"), (0x004D, other)]).is_err());
        }
    }

    #[test]
    fn upstream_overlap_is_only_with_consumed_core_positions() {
        for tag in [
            tag::D_SECRET_PATH,
            tag::D_TRUST_PATH,
            tag::D_REF_PATH,
            tag::D_DEST_PATH,
            tag::D_PUBLIC_URL_PATH,
            tag::D_CALLER_UPSTREAMS_PATH,
        ] {
            for path in [
                "",
                "/servers",
                "/servers/*",
                "/servers/*/auth",
                "/servers/member/tls/client_identity",
                "/servers/*/allow_private",
                "/servers/*/*",
            ] {
                assert!(
                    decode(KindCode::Plane, &[(0x004D, "/servers/*"), (tag, path)]).is_err(),
                    "{tag:x} {path}"
                );
            }
            assert!(decode(
                KindCode::Plane,
                &[(0x004D, "/servers/*"), (tag, "/servers/*/custom_headers/*")]
            )
            .is_ok());
        }
    }

    #[test]
    fn escaped_tokens_and_root_map_are_supported() {
        assert!(decode(KindCode::Plane, &[(0x004D, "/*")]).is_ok());
        assert!(decode(
            KindCode::Plane,
            &[
                (0x004D, "/s~1ervers~0/*"),
                (tag::D_SECRET_PATH, "/s~1ervers~0/*/auth/secret")
            ]
        )
        .is_err());
        let described = decode(KindCode::Plane, &[(0x004D, "/s~1ervers~0/*")]).unwrap();
        assert!(described
            .items
            .iter()
            .any(|(tag, bytes)| *tag == 0x004D && bytes == b"/s~1ervers~0/*"));
        assert!(decode(KindCode::Store, &[]).is_ok());
    }
}
