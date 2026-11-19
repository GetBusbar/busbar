// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REFERENCE AUTH (auth 4.0): the smallest image that uses what the revision changes for an auth plugin:
//! the sync `verify` over the one call shape (head `flags, _r, now_s`; texts `method, path, query, authority,
//! peer`; blobs `headers[pairs], tls_peer_cert, body, issued`) and the host's HMAC OVER PARTS (core 3.0), which
//! `busbar-auth-webhook-signature` uses so that a signed body is MACed where it lies and never copied.
//!
//! The scheme, chosen so the boundary test needs no second MAC implementation: the signed message is the value
//! of the `x-ref-id` header followed by the body, handed to the host as two parts; the presented signature is
//! the lowercase hex of HMAC-SHA256 under the configured key, in `x-ref-signature`. With key `Jefe`, id
//! `what do ya want ` and body `for nothing?` the two parts concatenate to RFC 4231 test case 2, whose tag is
//! published: a host whose parts MAC is not the MAC of the concatenation, an adapter that hands the body in
//! the wrong blob, or a header list that is not the pair list, all fail the one known answer.
//!
//! No credential header: REFUSED NOT_MINE. A malformed or wrong signature: REFUSED BAD_CREDENTIAL. A match:
//! ID_SUBJECT = the configured subject.

use std::collections::HashMap;

use busbar_plugin_abi::auth::{self, AuthReq};
use busbar_plugin_abi::fail::refused::R_CONFIG;
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::{Hash, Host, HostExt};
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{tag as record, Out, Writer};
use busbar_plugin_abi::Auth;

/// The header that carries the signed id.
pub const ID_HEADER: &str = "x-ref-id";
/// The header that carries the signature (the credential header this plugin declares).
pub const SIGNATURE_HEADER: &str = "x-ref-signature";

/// The reference auth: one key, one subject.
pub struct RefAuth {
    key: Vec<u8>,
    subject: String,
}

fn read(config: &[u8]) -> Result<(Vec<u8>, String), Fail> {
    let mut bag =
        busbar_contract::json::parse::<HashMap<String, String>>(config).map_err(|_| {
            Fail::refused_because(
                R_CONFIG,
                "config must be {\"key\": text, \"subject\": text}",
            )
        })?;
    match (bag.remove("key"), bag.remove("subject")) {
        (Some(key), Some(subject)) if !key.is_empty() && !subject.is_empty() && bag.is_empty() => {
            Ok((key.into_bytes(), subject))
        }
        _ => Err(Fail::refused_because(
            R_CONFIG,
            "config must be {\"key\": text, \"subject\": text}, both non-empty",
        )),
    }
}

/// The 32 bytes a 64-digit lowercase hex text names; `None` for any other text.
fn tag_of(hex: &[u8]) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut tag = [0u8; 32];
    for (byte, pair) in tag.iter_mut().zip(hex.chunks_exact(2)) {
        *byte = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(tag)
}

impl Open for RefAuth {
    async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        let (key, subject) = config.with(read)?;
        Ok(RefAuth { key, subject })
    }

    fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        read(config).map(|_| ())
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(
            r#"{"type":"object","required":["key","subject"],"additionalProperties":false,"properties":{"key":{"type":"string","minLength":1},"subject":{"type":"string","minLength":1}}}"#,
        );
        d.methods(auth::M_VERIFY);
        d.facts(auth::FB_NEEDS_BODY);
        d.item_text(auth::tag::D_CRED_HEADER, SIGNATURE_HEADER);
    }
}

impl Auth for RefAuth {
    fn verify(&self, h: &Host, req: &AuthReq<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
        let header = |name: &str| {
            req.headers
                .get()
                .iter()
                .find(|pair| pair.name.get().eq_ignore_ascii_case(name))
                .map(|pair| pair.value.get())
        };
        let Some(presented) = header(SIGNATURE_HEADER) else {
            return Err(Fail::refused(auth::NOT_MINE));
        };
        let id = header(ID_HEADER).unwrap_or_default();
        // The message is two borrowed parts: the id where the header lies, the body where the host lent it.
        let expected = h
            .hmac_parts(Hash::Sha256, &self.key, &[id, req.body.get()])
            .map_err(Fail::from)?;
        match tag_of(presented.trim_ascii()) {
            Some(tag) if expected.ct_eq(&tag) => out
                .put_text(record::ID_SUBJECT, &self.subject)
                .map_err(Fail::from),
            _ => Err(Fail::refused(auth::BAD_CREDENTIAL)),
        }
    }
}

busbar_plugin_abi::plugin!(Auth, RefAuth, name: "reference-auth");
