// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Auth request encoders and answer/describe decoders (IF §8.8, §8.3).

use busbar_plugin_abi::auth::{self as abi, tag as t, IssuedShapeRec};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::records::{tag, Full, RecErr, Records, U32Rec, Writer};

use crate::ports::auth::{AuthIn, IssuedShape, LoginIn, ServeIn, ServeOut, UpstreamIn};

/// The longest id prefix a shape may carry, the id length ceiling and the secret length range (IF §8.3).
const PREFIX_MAX: usize = 16;
const ID_LEN_MAX: usize = 128;
const SECRET_LEN: core::ops::RangeInclusive<usize> = 16..=256;

/// ASCII graphic: 0x21..=0x7E.
fn graphic(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_graphic())
}

/// 2..=94 distinct ASCII graphic characters.
fn alphabet(s: &str) -> bool {
    let mut seen = [false; 128];
    for b in s.bytes() {
        if !b.is_ascii_graphic() || core::mem::replace(&mut seen[usize::from(b)], true) {
            return false;
        }
    }
    (2..=94).contains(&s.len())
}

/// Round 12: D_ISSUED_KIND with its D_ISSUED_SHAPE (validated as §8.3 says), or None when neither is declared.
/// Either one without the other, a second of either, a shape whose tail is not exactly three TEXT records, a
/// prefix that is not ASCII graphic or is over 16 bytes, an alphabet that is not 2..=94 distinct ASCII graphic
/// characters, an `id_len` outside (prefix length, 128] or a `secret_len` outside 16..=256 is RecErr.
pub fn decode_issued_shape(
    describe: Records<'_>,
) -> Result<Option<(Box<str>, IssuedShape)>, RecErr> {
    let mut kind: Option<&str> = None;
    let mut shape: Option<IssuedShape> = None;
    for rec in describe {
        let rec = rec?;
        match rec.tag {
            t::D_ISSUED_KIND => {
                if kind.replace(rec.text()?).is_some() {
                    return Err(RecErr::Size);
                }
            }
            t::D_ISSUED_SHAPE => {
                if shape.is_some() {
                    return Err(RecErr::Size);
                }
                let (head, tail) = rec.pod_tail::<IssuedShapeRec>()?;
                let mut parts = Records::new(tail);
                let mut text = || -> Result<&str, RecErr> {
                    match parts.next_rec() {
                        Some(Ok(r)) if r.tag == tag::TEXT => r.text(),
                        Some(Ok(r)) => Err(RecErr::Unknown(r.tag)),
                        Some(Err(e)) => Err(e),
                        None => Err(RecErr::Size),
                    }
                };
                let (prefix, ids, secrets) = (text()?, text()?, text()?);
                if parts.next_rec().is_some() {
                    return Err(RecErr::Size);
                }
                let id_len = usize::try_from(head.id_len).map_err(|_| RecErr::Size)?;
                let secret_len = usize::try_from(head.secret_len).map_err(|_| RecErr::Size)?;
                if prefix.len() > PREFIX_MAX
                    || !graphic(prefix)
                    || !alphabet(ids)
                    || !alphabet(secrets)
                    || id_len <= prefix.len()
                    || id_len > ID_LEN_MAX
                    || !SECRET_LEN.contains(&secret_len)
                {
                    return Err(RecErr::Size);
                }
                shape = Some(IssuedShape {
                    id_prefix: prefix.into(),
                    id_len,
                    id_alphabet: ids.into(),
                    secret_len,
                    secret_alphabet: secrets.into(),
                });
            }
            _ => {}
        }
    }
    match (kind, shape) {
        (None, None) => Ok(None),
        (Some(k), Some(s)) => Ok(Some((k.into(), s))),
        _ => Err(RecErr::Size),
    }
}

/// verify_io: Q_METHOD, Q_PATH, Q_QUERY, Q_AUTHORITY, PAIR* (headers), Q_PEER, Q_TLS_CERT, Q_BODY, Q_ISSUED?
/// (only after a lookup), then FACT(F_NOW_S): `AuthReq`'s fields in order.
pub fn encode_verify_io(
    w: &mut impl Writer,
    r: &AuthIn<'_>,
    issued: Option<&[u8]>,
) -> Result<(), Full> {
    w.put_text(t::Q_METHOD, r.method)?;
    w.put_text(t::Q_PATH, r.path)?;
    w.put_text(t::Q_QUERY, r.query)?;
    w.put_text(t::Q_AUTHORITY, r.authority)?;
    for h in r.headers {
        w.put_pair(tag::PAIR, h.name.get(), h.value.get())?;
    }
    w.put_text(t::Q_PEER, r.peer)?;
    w.put(t::Q_TLS_CERT, r.tls_peer_cert)?;
    w.put(t::Q_BODY, r.body)?;
    if let Some(id) = issued {
        w.put(t::Q_ISSUED, id)?;
    }
    w.put_fact(abi::F_NOW_S, r.now_s)
}

/// login. BEGIN: L_RETURN_TO, L_REDIRECT_URI, L_STATE_KEY, L_CODE_CHALLENGE, L_NONCE, L_CONNECT?, L_SCOPE?.
/// COMPLETE: L_CALLBACK_QUERY, L_STATE, L_REDIRECT_URI, L_CODE_VERIFIER, L_NONCE, L_CONNECT?.
/// CREDENTIAL: L_USERNAME, L_PASSWORD.
pub fn encode_login(w: &mut impl Writer, l: &LoginIn<'_>) -> Result<(), Full> {
    match *l {
        LoginIn::Begin {
            return_to,
            redirect_uri,
            state_key,
            code_challenge,
            nonce,
            connect,
            scope,
        } => {
            w.put_text(t::L_RETURN_TO, return_to)?;
            w.put_text(t::L_REDIRECT_URI, redirect_uri)?;
            w.put_text(t::L_STATE_KEY, state_key)?;
            w.put_text(t::L_CODE_CHALLENGE, code_challenge)?;
            w.put_text(t::L_NONCE, nonce)?;
            if let Some(c) = connect {
                w.put_text(t::L_CONNECT, c)?;
            }
            if let Some(s) = scope {
                w.put_text(t::L_SCOPE, s)?;
            }
            Ok(())
        }
        LoginIn::Complete {
            callback_query,
            state,
            redirect_uri,
            code_verifier,
            nonce,
            connect,
        } => {
            w.put_text(t::L_CALLBACK_QUERY, callback_query)?;
            w.put(t::L_STATE, state)?;
            w.put_text(t::L_REDIRECT_URI, redirect_uri)?;
            w.put_text(t::L_CODE_VERIFIER, code_verifier)?;
            w.put_text(t::L_NONCE, nonce)?;
            if let Some(c) = connect {
                w.put_text(t::L_CONNECT, c)?;
            }
            Ok(())
        }
        LoginIn::Credential { username, password } => {
            w.put_text(t::L_USERNAME, username)?;
            w.put(t::L_PASSWORD, password)
        }
    }
}

/// outbound: O_METHOD, O_URL, PAIR* (headers), O_BODY_SHA256?, O_CALLER_CRED*, O_SCOPE?, O_CALLER_GRANT?.
/// Round 23 (R3): ends with FACT(F_MIN_VALID_S) = `u.min_valid_s`, on every call.
pub fn encode_outbound(w: &mut impl Writer, u: &UpstreamIn<'_>) -> Result<(), Full> {
    w.put_text(t::O_METHOD, u.method)?;
    w.put_text(t::O_URL, u.url)?;
    for h in u.headers {
        w.put_pair(tag::PAIR, h.name.get(), h.value.get())?;
    }
    if let Some(sum) = &u.body_sha256 {
        w.put(t::O_BODY_SHA256, sum)?;
    }
    for c in u.caller_cred {
        w.put_pair(t::O_CALLER_CRED, c.name.get(), c.value.get())?;
    }
    if let Some(s) = u.scope {
        w.put_text(t::O_SCOPE, s)?;
    }
    if let Some(g) = u.caller_grant {
        w.put(t::O_CALLER_GRANT, g)?;
    }
    w.put_fact(abi::F_MIN_VALID_S, u64::from(u.min_valid_s))
}

/// Round 29, `serve`: Q_METHOD, Q_PATH, Q_QUERY, PAIR* (headers), Q_BODY, Q_CLIENT.
pub fn encode_serve(w: &mut impl Writer, s: &ServeIn<'_>) -> Result<(), Full> {
    w.put_text(t::Q_METHOD, s.method)?;
    w.put_text(t::Q_PATH, s.path)?;
    w.put_text(t::Q_QUERY, s.query)?;
    for (name, value) in s.headers {
        w.put_pair(tag::PAIR, name, value)?;
    }
    w.put(t::Q_BODY, s.body)?;
    w.put_text(t::Q_CLIENT, s.client)
}

/// Round 29, a `serve` OK answer: SV_STATUS (200..=599), SV_HEADER*, SV_BODY?.
pub fn decode_serve(a: &Answer<'_>) -> Result<ServeOut, RecErr> {
    decode_serve_records(a.records())
}

/// [`decode_serve`] over the answer's records. METRIC records (generic, decoded once by `decode_metrics`) are
/// skipped; any other record, a record out of order, a second SV_STATUS or SV_BODY, or a status outside
/// 200..=599 is RecErr; no SV_STATUS is `Truncated`.
fn decode_serve_records(records: Records<'_>) -> Result<ServeOut, RecErr> {
    let mut status: Option<u16> = None;
    let mut headers = Vec::new();
    let mut body: Option<Vec<u8>> = None;
    for rec in records {
        let rec = rec?;
        match rec.tag {
            tag::METRIC => {}
            t::SV_STATUS if status.is_none() => {
                let v = rec.pod::<U32Rec>()?;
                if v._r != 0 {
                    return Err(RecErr::Reserved);
                }
                status = u16::try_from(v.value)
                    .ok()
                    .filter(|s| (200..=599).contains(s));
                if status.is_none() {
                    return Err(RecErr::Size);
                }
            }
            t::SV_HEADER if status.is_some() && body.is_none() => {
                let (name, value) = rec.pair()?;
                headers.push((Box::from(name), value.to_vec()));
            }
            t::SV_BODY if status.is_some() && body.is_none() => body = Some(rec.body.to_vec()),
            other => return Err(RecErr::Unknown(other)),
        }
    }
    Ok(ServeOut {
        status: status.ok_or(RecErr::Truncated)?,
        headers,
        body: body.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::auth::{self as abi, tag as t, IssuedShapeRec};
    use busbar_plugin_abi::records::{tag, Reply, U32Rec};
    use busbar_plugin_abi::types::{Bytes, Pair, Str};

    fn recs(r: &Reply) -> Vec<(u16, Vec<u8>)> {
        Records::new(r.as_bytes())
            .map(|x| {
                let x = x.unwrap();
                (x.tag, x.body.to_vec())
            })
            .collect()
    }

    fn tags(r: &Reply) -> Vec<u16> {
        recs(r).into_iter().map(|(t, _)| t).collect()
    }

    fn fact(key: u32, value: u64) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&key.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&value.to_le_bytes());
        b
    }

    fn auth_in<'a>(headers: &'a [Pair<'a>]) -> AuthIn<'a> {
        AuthIn {
            method: "POST",
            path: "/v1/x",
            query: "a=1",
            authority: "gw.example",
            headers,
            peer: "10.0.0.1:443",
            tls_peer_cert: b"cert",
            body: b"{}",
            now_s: 1_700_000_000,
        }
    }

    #[test]
    fn verify_io_writes_the_request_fields_in_order() {
        let mut w = Reply::new();
        encode_verify_io(&mut w, &auth_in(&[]), None).unwrap();
        assert_eq!(
            recs(&w),
            vec![
                (t::Q_METHOD, b"POST".to_vec()),
                (t::Q_PATH, b"/v1/x".to_vec()),
                (t::Q_QUERY, b"a=1".to_vec()),
                (t::Q_AUTHORITY, b"gw.example".to_vec()),
                (t::Q_PEER, b"10.0.0.1:443".to_vec()),
                (t::Q_TLS_CERT, b"cert".to_vec()),
                (t::Q_BODY, b"{}".to_vec()),
                (abi_tag_fact(), fact(abi::F_NOW_S, 1_700_000_000)),
            ]
        );
    }

    fn abi_tag_fact() -> u16 {
        tag::FACT
    }

    #[test]
    fn verify_io_adds_q_issued_before_the_clock_only_after_a_lookup() {
        let mut w = Reply::new();
        encode_verify_io(&mut w, &auth_in(&[]), Some(b"AKIAEXAMPLE")).unwrap();
        let got = recs(&w);
        assert_eq!(got[7], (t::Q_ISSUED, b"AKIAEXAMPLE".to_vec()));
        assert_eq!(got[8].0, tag::FACT);
        assert_eq!(got.len(), 9);
    }

    #[test]
    #[ignore = "UNSAFE-MIN: Str::get/Bytes::get on a non-empty view are held until W1-U0"]
    fn verify_io_writes_each_header_as_a_pair_between_authority_and_peer() {
        let headers = [Pair {
            name: Str::new("authorization"),
            value: Bytes::new(b"Bearer x"),
        }];
        let mut w = Reply::new();
        encode_verify_io(&mut w, &auth_in(&headers), None).unwrap();
        assert_eq!(
            tags(&w)[..6],
            [
                t::Q_METHOD,
                t::Q_PATH,
                t::Q_QUERY,
                t::Q_AUTHORITY,
                tag::PAIR,
                t::Q_PEER
            ]
        );
    }

    #[test]
    fn login_begin_writes_the_core_minted_inputs_and_the_optional_pair() {
        let begin = |connect, scope| LoginIn::Begin {
            return_to: "/after",
            redirect_uri: "https://gw/cb",
            state_key: "sk",
            code_challenge: "ch",
            nonce: "n",
            connect,
            scope,
        };
        let mut w = Reply::new();
        encode_login(&mut w, &begin(None, None)).unwrap();
        assert_eq!(
            tags(&w),
            [
                t::L_RETURN_TO,
                t::L_REDIRECT_URI,
                t::L_STATE_KEY,
                t::L_CODE_CHALLENGE,
                t::L_NONCE
            ]
        );
        let mut w = Reply::new();
        encode_login(&mut w, &begin(Some("up"), Some("a b"))).unwrap();
        let got = recs(&w);
        assert_eq!(got[5], (t::L_CONNECT, b"up".to_vec()));
        assert_eq!(got[6], (t::L_SCOPE, b"a b".to_vec()));
    }

    #[test]
    fn login_complete_and_credential_write_their_inputs() {
        let mut w = Reply::new();
        encode_login(
            &mut w,
            &LoginIn::Complete {
                callback_query: "code=1&state=2",
                state: b"\x00\x01",
                redirect_uri: "https://gw/cb",
                code_verifier: "v",
                nonce: "n",
                connect: None,
            },
        )
        .unwrap();
        assert_eq!(
            recs(&w),
            vec![
                (t::L_CALLBACK_QUERY, b"code=1&state=2".to_vec()),
                (t::L_STATE, vec![0, 1]),
                (t::L_REDIRECT_URI, b"https://gw/cb".to_vec()),
                (t::L_CODE_VERIFIER, b"v".to_vec()),
                (t::L_NONCE, b"n".to_vec()),
            ]
        );
        let mut w = Reply::new();
        encode_login(
            &mut w,
            &LoginIn::Credential {
                username: "ann",
                password: b"pw",
            },
        )
        .unwrap();
        assert_eq!(
            recs(&w),
            vec![
                (t::L_USERNAME, b"ann".to_vec()),
                (t::L_PASSWORD, b"pw".to_vec())
            ]
        );
    }

    fn upstream<'a>() -> UpstreamIn<'a> {
        UpstreamIn {
            method: "GET",
            url: "https://up/x",
            headers: &[],
            body_sha256: Some([7; 32]),
            caller_cred: &[],
            scope: Some("s1 s2"),
            caller_grant: Some(b"grant"),
            min_valid_s: 30,
        }
    }

    #[test]
    fn outbound_writes_the_binding_inputs_and_the_margin_fact() {
        let mut w = Reply::new();
        encode_outbound(&mut w, &upstream()).unwrap();
        assert_eq!(
            recs(&w),
            vec![
                (t::O_METHOD, b"GET".to_vec()),
                (t::O_URL, b"https://up/x".to_vec()),
                (t::O_BODY_SHA256, vec![7; 32]),
                (t::O_SCOPE, b"s1 s2".to_vec()),
                (t::O_CALLER_GRANT, b"grant".to_vec()),
                (tag::FACT, fact(abi::F_MIN_VALID_S, 30)),
            ]
        );
    }

    #[test]
    fn serve_writes_the_routed_request() {
        let headers: [(&str, &[u8]); 1] = [("content-type", b"application/scim+json")];
        let mut w = Reply::new();
        encode_serve(
            &mut w,
            &ServeIn {
                method: "POST",
                path: "/Users",
                query: "",
                headers: &headers,
                body: b"{}",
                client: "okta",
            },
        )
        .unwrap();
        assert_eq!(
            tags(&w),
            [
                t::Q_METHOD,
                t::Q_PATH,
                t::Q_QUERY,
                tag::PAIR,
                t::Q_BODY,
                t::Q_CLIENT
            ]
        );
        assert_eq!(recs(&w)[5], (t::Q_CLIENT, b"okta".to_vec()));
    }

    fn status(w: &mut Reply, v: u32) {
        w.put_pod(t::SV_STATUS, &U32Rec { value: v, _r: 0 })
            .unwrap();
    }

    #[test]
    fn serve_answer_decodes_status_headers_and_body() {
        let mut w = Reply::new();
        status(&mut w, 201);
        w.put_pair(t::SV_HEADER, "location", b"/Users/1").unwrap();
        w.put_pair(t::SV_HEADER, "etag", b"W/1").unwrap();
        w.put(t::SV_BODY, b"{\"id\":1}").unwrap();
        let out = decode_serve_records(Records::new(w.as_bytes())).unwrap();
        assert_eq!(out.status, 201);
        assert_eq!(
            out.headers,
            vec![
                (Box::from("location"), b"/Users/1".to_vec()),
                (Box::from("etag"), b"W/1".to_vec())
            ]
        );
        assert_eq!(out.body, b"{\"id\":1}");
    }

    #[test]
    fn serve_answer_without_a_body_has_an_empty_one() {
        let mut w = Reply::new();
        status(&mut w, 204);
        let out = decode_serve_records(Records::new(w.as_bytes())).unwrap();
        assert!(out.headers.is_empty() && out.body.is_empty());
    }

    #[test]
    fn serve_answer_rejects_what_the_grammar_forbids() {
        let bad = |f: &dyn Fn(&mut Reply)| {
            let mut w = Reply::new();
            f(&mut w);
            match decode_serve_records(Records::new(w.as_bytes())) {
                Err(e) => e,
                Ok(_) => panic!("decode_serve_records accepted a forbidden answer"),
            }
        };
        assert!(matches!(bad(&|_| {}), RecErr::Truncated));
        assert!(matches!(bad(&|w| status(w, 199)), RecErr::Size));
        assert!(matches!(bad(&|w| status(w, 600)), RecErr::Size));
        assert!(matches!(
            bad(&|w| {
                status(w, 200);
                status(w, 200)
            }),
            RecErr::Unknown(_)
        ));
        assert!(matches!(
            bad(&|w| w.put(t::SV_BODY, b"x").unwrap()),
            RecErr::Unknown(_)
        ));
        assert!(matches!(
            bad(&|w| {
                status(w, 200);
                w.put(t::SV_BODY, b"x").unwrap();
                w.put_pair(t::SV_HEADER, "a", b"b").unwrap()
            }),
            RecErr::Unknown(_)
        ));
        assert!(matches!(
            bad(&|w| {
                status(w, 200);
                w.put_text(t::STRIP, "x").unwrap()
            }),
            RecErr::Unknown(_)
        ));
    }

    const AKIA_IDS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const B64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn describe(kind: Option<&str>, shape: Option<(u32, u32, &[&str])>, extra_kind: bool) -> Reply {
        let mut w = Reply::new();
        w.put_pod(
            busbar_plugin_abi::records::tag::D_METHODS,
            &busbar_plugin_abi::records::MaskRec { mask: 1 },
        )
        .unwrap();
        if let Some(k) = kind {
            w.put_text(t::D_ISSUED_KIND, k).unwrap();
            if extra_kind {
                w.put_text(t::D_ISSUED_KIND, k).unwrap();
            }
        }
        w.put_text(t::D_OUTBOUND_STYLE, "sigv4").unwrap();
        if let Some((id_len, secret_len, texts)) = shape {
            let mut tail = Reply::new();
            for s in texts {
                tail.put_text(tag::TEXT, s).unwrap();
            }
            w.put_pod_tail(
                t::D_ISSUED_SHAPE,
                &IssuedShapeRec { id_len, secret_len },
                tail.as_bytes(),
            )
            .unwrap();
        }
        w
    }

    #[test]
    fn issued_shape_none_when_neither_is_declared() {
        let w = describe(None, None, false);
        assert_eq!(decode_issued_shape(Records::new(w.as_bytes())), Ok(None));
    }

    #[test]
    fn issued_shape_decodes_sigv4() {
        let w = describe(
            Some("sigv4"),
            Some((20, 40, &["AKIA", AKIA_IDS, B64])),
            false,
        );
        let (kind, shape) = decode_issued_shape(Records::new(w.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(&*kind, "sigv4");
        assert_eq!(
            shape,
            IssuedShape {
                id_prefix: "AKIA".into(),
                id_len: 20,
                id_alphabet: AKIA_IDS.into(),
                secret_len: 40,
                secret_alphabet: B64.into(),
            }
        );
    }

    #[test]
    fn issued_shape_refuses_every_malformed_declaration() {
        let ok: &[&str] = &["AKIA", AKIA_IDS, B64];
        let bad = |kind, shape, dup| {
            let w = describe(kind, shape, dup);
            decode_issued_shape(Records::new(w.as_bytes())).is_err()
        };
        assert!(bad(Some("k"), None, false), "kind without shape");
        assert!(bad(None, Some((20, 40, ok)), false), "shape without kind");
        assert!(bad(Some("k"), Some((20, 40, ok)), true), "two kinds");
        assert!(bad(Some("k"), Some((20, 40, &["AKIA", AKIA_IDS])), false));
        assert!(bad(
            Some("k"),
            Some((20, 40, &["AKIA", AKIA_IDS, B64, "x"])),
            false
        ));
        assert!(
            bad(Some("k"), Some((4, 40, ok)), false),
            "id_len not above the prefix"
        );
        assert!(
            bad(Some("k"), Some((129, 40, ok)), false),
            "id_len over 128"
        );
        assert!(bad(Some("k"), Some((20, 15, ok)), false), "secret under 16");
        assert!(
            bad(Some("k"), Some((20, 257, ok)), false),
            "secret over 256"
        );
        assert!(
            bad(Some("k"), Some((20, 40, &["AKIA", "a", B64])), false),
            "1-symbol alphabet"
        );
        assert!(
            bad(Some("k"), Some((20, 40, &["AKIA", "aab", B64])), false),
            "repeated symbol"
        );
        assert!(
            bad(Some("k"), Some((20, 40, &["AKIA", "a b", B64])), false),
            "space in alphabet"
        );
        assert!(
            bad(Some("k"), Some((20, 40, &["A KI", AKIA_IDS, B64])), false),
            "space in prefix"
        );
        let long_prefix = "A".repeat(17);
        let long_prefix_shape = [long_prefix.as_str(), AKIA_IDS, B64];
        assert!(
            bad(Some("k"), Some((40, 40, &long_prefix_shape[..])), false),
            "prefix over 16"
        );
        assert!(
            !bad(Some("k"), Some((5, 16, &["", AKIA_IDS, B64])), false),
            "empty prefix is allowed"
        );
    }
}
