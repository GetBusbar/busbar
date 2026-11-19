// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::refusal::{Refusal, RefusalCode};
use busbar_plugin_abi::{records::tag, types::KindCode};

fn bad() -> Refusal {
    Refusal::new(
        RefusalCode::DescribeInvalid,
        "describe.upstream_path",
        "invalid or overlapping declaration",
        "at most four plane registration pointers, disjoint from consumed core positions",
    )
}

/// The decoded tokens of RFC 6901 pointer `text` (`""` = no token); `None` when it is not one.
pub(crate) fn tokens(text: &str) -> Option<Vec<String>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    text.strip_prefix('/')?
        .split('/')
        .map(|token| {
            let mut decoded = String::new();
            let mut chars = token.chars();
            while let Some(c) = chars.next() {
                decoded.push(if c == '~' {
                    match chars.next()? {
                        '0' => '~',
                        '1' => '/',
                        _ => return None,
                    }
                } else {
                    c
                });
            }
            Some(decoded)
        })
        .collect()
}

// Wildcards intersect literal member names as well as other wildcards. Equal prefixes overlap even when
// one declaration is above the other; comparison happens after RFC 6901 decoding.
fn overlaps(a: &[String], b: &[String]) -> bool {
    a.iter().zip(b).all(|(a, b)| a == b || a == "*" || b == "*")
}

pub(crate) fn validate(kind: KindCode, items: &[(u16, Vec<u8>)]) -> Result<(), Refusal> {
    let mut upstreams: Vec<Vec<String>> = Vec::new();
    for (_, body) in items
        .iter()
        .filter(|(t, _)| *t == busbar_plugin_abi::plane::tag::D_UPSTREAM_PATH)
    {
        let text = core::str::from_utf8(body).map_err(|_| bad())?;
        let path = tokens(text).ok_or_else(bad)?;
        if kind != KindCode::Plane
            || upstreams.len() == 4
            || path.last().map(String::as_str) != Some("*")
            || path[..path.len().saturating_sub(1)]
                .iter()
                .any(|t| t == "*")
            || upstreams.iter().any(|prior| overlaps(prior, &path))
        {
            return Err(bad());
        }
        upstreams.push(path);
    }
    if upstreams.is_empty() {
        return Ok(());
    }
    for (t, body) in items {
        if ![
            tag::D_SECRET_PATH,
            tag::D_TRUST_PATH,
            tag::D_REF_PATH,
            busbar_plugin_abi::plane::tag::D_PUBLIC_URL_PATH,
            busbar_plugin_abi::plane::tag::D_CALLER_UPSTREAMS_PATH,
        ]
        .contains(t)
        {
            continue;
        }
        let other = tokens(core::str::from_utf8(body).map_err(|_| bad())?).ok_or_else(bad)?;
        for upstream in &upstreams {
            for field in [
                "url",
                "command",
                "tls",
                "auth",
                "upstream_credentials",
                "allow_private",
            ] {
                let mut consumed = upstream.clone();
                consumed.push(field.into());
                if overlaps(&consumed, &other) {
                    return Err(bad());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use busbar_plugin_abi::records::{tag, MaskRec, Records, Reply, Writer};
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
            busbar_plugin_abi::plane::tag::D_PUBLIC_URL_PATH,
            busbar_plugin_abi::plane::tag::D_CALLER_UPSTREAMS_PATH,
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
        assert_eq!(
            described
                .paths(busbar_plugin_abi::plane::tag::D_UPSTREAM_PATH)
                .collect::<Vec<_>>(),
            ["/s~1ervers~0/*"]
        );
        assert!(decode(KindCode::Store, &[]).is_ok());
    }
}
