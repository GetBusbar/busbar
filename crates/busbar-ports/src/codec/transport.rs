// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Transport request encoders and answer decoders (IF §8.8). `encode_path` and `encode_keying` write the
//! EV_PATH and EV_KEYING arguments, one record each (R6b, busbar#256).

use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::records::{tag as generic, Full, RecErr, Records, Writer};
use busbar_plugin_abi::transport::{tag, KeyingRec, PathRec, ROLE_CLIENT, ROLE_SERVER};

/// The most ALPN ids, and the most default lines, one `offer` answer may carry (§8.7).
const OFFER_MAX: usize = 8;
/// An ALPN protocol id is 1..=255 bytes (RFC 7301 §3.1).
const ALPN_MAX: usize = 255;

/// Validate and own the native initial-listener declarations before an instance can be selected.
/// Other descriptor items are not interpreted here; slots are exact, case-sensitive configuration names.
pub fn decode_listener_slots<'a>(
    facts: u64,
    items: impl IntoIterator<Item = (u16, &'a [u8])>,
) -> Result<Box<[Box<str>]>, RecErr> {
    let mut slots: Vec<Box<str>> = Vec::new();
    for (item, bytes) in items {
        if item != tag::D_LISTENER_SLOT {
            continue;
        }
        let slot = core::str::from_utf8(bytes).map_err(|_| RecErr::Utf8)?;
        if slots.len() == 64
            || slot.is_empty()
            || slot.len() > 128
            || !slot
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || slots.iter().any(|prior| prior.as_ref() == slot)
            || facts & busbar_plugin_abi::transport::FB_SERVER == 0
            || facts & busbar_plugin_abi::transport::FB_DATAGRAM != 0
        {
            return Err(RecErr::Size);
        }
        slots.push(slot.into());
    }
    Ok(slots.into())
}

pub fn encode_path(w: &mut impl Writer, path: u32, flags: u32, addr: &str) -> Result<(), Full> {
    w.put_pod_tail(tag::EVENT_PATH, &PathRec { path, flags }, addr.as_bytes())
}

pub fn encode_keying(
    w: &mut impl Writer,
    path: u32,
    profile: u32,
    material: &[u8],
) -> Result<(), Full> {
    w.put_pod_tail(tag::EVENT_KEYING, &KeyingRec { path, profile }, material)
}

/// Round 9: the `offer` answer (ALPN*, each 1..=255 bytes, at most 8). Round 22: then, for ROLE_CLIENT only,
/// PAIR* (at most 8, names lowercase token characters, values without CR/LF) as `defaults`; anything else,
/// or PAIR for ROLE_SERVER, BadRecords.
///
/// W1-A11: every grammar breach (role, tag, order, count, length, charset) is `RecErr::Size`, never
/// `RecErr::Unknown`, because §8.7 makes any other tag BadRecords, not UnknownTag. Text that is not UTF-8 is
/// `RecErr::Utf8`, and a framing error is returned as the reader gave it. A METRIC record (allowed in any OK
/// answer, §3) is passed over; `decode_metrics` reads it.
pub fn decode_offer(a: &Answer<'_>, role: u32) -> Result<Offer, RecErr> {
    offer_from(a.records(), role)
}

pub struct Offer {
    pub alpn: Box<[Box<str>]>,
    pub defaults: Box<[(Box<str>, Box<str>)]>,
}

/// `decode_offer` over the answer's records (the seam the tests drive, since only W1-H1 builds an `Answer`).
fn offer_from(recs: Records<'_>, role: u32) -> Result<Offer, RecErr> {
    if role != ROLE_SERVER && role != ROLE_CLIENT {
        return Err(RecErr::Size);
    }
    let mut alpn: Vec<Box<str>> = Vec::new();
    let mut defaults: Vec<(Box<str>, Box<str>)> = Vec::new();
    for rec in recs {
        let rec = rec?;
        match rec.tag {
            generic::METRIC => {}
            tag::ALPN if defaults.is_empty() && alpn.len() < OFFER_MAX => {
                let id = rec.text()?;
                if id.is_empty() || id.len() > ALPN_MAX {
                    return Err(RecErr::Size);
                }
                alpn.push(Box::from(id));
            }
            generic::PAIR if role == ROLE_CLIENT && defaults.len() < OFFER_MAX => {
                let (name, value) = rec.pair()?;
                let value = core::str::from_utf8(value).map_err(|_| RecErr::Utf8)?;
                if !is_default_name(name) || value.contains(['\r', '\n']) {
                    return Err(RecErr::Size);
                }
                defaults.push((Box::from(name), Box::from(value)));
            }
            _ => return Err(RecErr::Size),
        }
    }
    Ok(Offer {
        alpn: alpn.into(),
        defaults: defaults.into(),
    })
}

/// A default line's name: one or more RFC 9110 token characters, no uppercase letter.
fn is_default_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::records::Reply;
    use busbar_plugin_abi::transport::ROLE_DATAGRAM;

    /// One `offer` answer's records, written by the codec's own writer.
    fn answer(f: impl FnOnce(&mut Reply) -> Result<(), Full>) -> Reply {
        let mut out = Reply::new();
        f(&mut out).expect("the test answer fits");
        out
    }

    fn decode(out: &Reply, role: u32) -> Result<Offer, RecErr> {
        offer_from(Records::new(out.as_bytes()), role)
    }

    fn alpn(offer: &Offer) -> Vec<&str> {
        offer.alpn.iter().map(|id| &**id).collect()
    }

    fn defaults(offer: &Offer) -> Vec<(&str, &str)> {
        offer
            .defaults
            .iter()
            .map(|(name, value)| (&**name, &**value))
            .collect()
    }

    /// R6b (busbar#256): an EV_PATH argument is exactly one record, tag 0x0117, body PathRec + address text.
    #[test]
    fn a_path_event_argument_is_one_event_path_record() {
        use busbar_plugin_abi::transport::PathRec;
        let mut out = Reply::new();
        encode_path(&mut out, 7, 3, "192.0.2.1:4000").expect("fits");
        let mut recs = Records::new(out.as_bytes());
        let rec = recs.next().expect("one record").expect("well framed");
        assert_eq!(rec.tag, 0x0117);
        let (p, tail) = rec.pod_tail::<PathRec>().expect("PathRec then tail");
        assert_eq!((p.path, p.flags), (7, 3));
        assert_eq!(tail, b"192.0.2.1:4000");
        assert!(recs.next().is_none(), "the argument is exactly one record");
    }

    /// R6b (busbar#256): an EV_KEYING argument is exactly one record, tag 0x0118, body KeyingRec + material.
    #[test]
    fn a_keying_event_argument_is_one_event_keying_record() {
        use busbar_plugin_abi::transport::KeyingRec;
        let mut out = Reply::new();
        encode_keying(&mut out, 9, 1, &[0xAB; 60]).expect("fits");
        let mut recs = Records::new(out.as_bytes());
        let rec = recs.next().expect("one record").expect("well framed");
        assert_eq!(rec.tag, 0x0118);
        let (k, tail) = rec.pod_tail::<KeyingRec>().expect("KeyingRec then tail");
        assert_eq!((k.path, k.profile), (9, 1));
        assert_eq!(tail, [0xAB; 60]);
        assert!(recs.next().is_none(), "the argument is exactly one record");
    }
    #[test]
    fn an_offer_reads_alpn_then_client_defaults() {
        let out = answer(|w| {
            w.put_text(tag::ALPN, "h2")?;
            w.put_text(tag::ALPN, "http/1.1")?;
            w.put_pair(generic::PAIR, "content-type", b"application/grpc")?;
            w.put_pair(generic::PAIR, "te", b"trailers")
        });
        let offer = decode(&out, ROLE_CLIENT).expect("a valid client offer");
        assert_eq!(alpn(&offer), ["h2", "http/1.1"]);
        assert_eq!(
            defaults(&offer),
            [("content-type", "application/grpc"), ("te", "trailers")]
        );
    }

    #[test]
    fn a_server_offer_is_alpn_only() {
        let out = answer(|w| w.put_text(tag::ALPN, "h2"));
        let offer = decode(&out, ROLE_SERVER).expect("a valid server offer");
        assert_eq!(alpn(&offer), ["h2"]);
        assert!(offer.defaults.is_empty());

        let out = answer(|w| {
            w.put_text(tag::ALPN, "h2")?;
            w.put_pair(generic::PAIR, "accept", b"*/*")
        });
        assert_eq!(decode(&out, ROLE_SERVER).err(), Some(RecErr::Size));
    }

    #[test]
    fn an_empty_answer_offers_no_alpn_on_either_side() {
        for role in [ROLE_SERVER, ROLE_CLIENT] {
            let offer = decode(&Reply::new(), role).expect("zero ALPN is a valid offer");
            assert!(offer.alpn.is_empty());
            assert!(offer.defaults.is_empty());
        }
    }

    #[test]
    fn alpn_ids_are_1_to_255_bytes_and_at_most_8() {
        let longest = "a".repeat(255);
        let out = answer(|w| w.put_text(tag::ALPN, &longest));
        assert_eq!(
            alpn(&decode(&out, ROLE_SERVER).expect("255 bytes")),
            [&*longest]
        );

        let too_long = "a".repeat(256);
        let out = answer(|w| w.put_text(tag::ALPN, &too_long));
        assert_eq!(decode(&out, ROLE_SERVER).err(), Some(RecErr::Size));

        let out = answer(|w| w.put_text(tag::ALPN, ""));
        assert_eq!(decode(&out, ROLE_CLIENT).err(), Some(RecErr::Size));

        let eight = answer(|w| (0..8).try_for_each(|_| w.put_text(tag::ALPN, "h2")));
        assert_eq!(
            decode(&eight, ROLE_SERVER).expect("eight ids").alpn.len(),
            8
        );
        let nine = answer(|w| (0..9).try_for_each(|_| w.put_text(tag::ALPN, "h2")));
        assert_eq!(decode(&nine, ROLE_SERVER).err(), Some(RecErr::Size));

        let out = answer(|w| w.put(tag::ALPN, &[0xFF]));
        assert_eq!(decode(&out, ROLE_SERVER).err(), Some(RecErr::Utf8));
    }

    #[test]
    fn defaults_are_at_most_8_lowercase_token_names_without_cr_or_lf() {
        let names = ["x-a!#$%&'*+-.^_`|~09", "accept"];
        let out = answer(|w| {
            names
                .iter()
                .try_for_each(|name| w.put_pair(generic::PAIR, name, b"v a l u e\t"))
        });
        let offer = decode(&out, ROLE_CLIENT).expect("token names");
        assert_eq!(defaults(&offer).len(), 2);

        for name in ["", "Accept", "x a", "x:a", "x\u{e9}"] {
            let out = answer(|w| w.put_pair(generic::PAIR, name, b"v"));
            assert_eq!(
                decode(&out, ROLE_CLIENT).err(),
                Some(RecErr::Size),
                "{name:?}"
            );
        }
        for value in [&b"a\rb"[..], b"a\nb", b"\r\n"] {
            let out = answer(|w| w.put_pair(generic::PAIR, "accept", value));
            assert_eq!(decode(&out, ROLE_CLIENT).err(), Some(RecErr::Size));
        }
        let out = answer(|w| w.put_pair(generic::PAIR, "accept", &[0xFF]));
        assert_eq!(decode(&out, ROLE_CLIENT).err(), Some(RecErr::Utf8));

        let empty_value = answer(|w| w.put_pair(generic::PAIR, "accept", b""));
        assert_eq!(
            defaults(&decode(&empty_value, ROLE_CLIENT).expect("an empty value")),
            [("accept", "")]
        );

        let eight = answer(|w| (0..8).try_for_each(|_| w.put_pair(generic::PAIR, "te", b"x")));
        assert_eq!(
            decode(&eight, ROLE_CLIENT)
                .expect("eight lines")
                .defaults
                .len(),
            8
        );
        let nine = answer(|w| (0..9).try_for_each(|_| w.put_pair(generic::PAIR, "te", b"x")));
        assert_eq!(decode(&nine, ROLE_CLIENT).err(), Some(RecErr::Size));
    }

    #[test]
    fn an_alpn_after_a_default_line_is_bad_records() {
        let out = answer(|w| {
            w.put_pair(generic::PAIR, "accept", b"*/*")?;
            w.put_text(tag::ALPN, "h2")
        });
        assert_eq!(decode(&out, ROLE_CLIENT).err(), Some(RecErr::Size));
    }

    /// §8.7 `offer`: any other role or tag is FAULT BadRecords, so the decoder never answers `Unknown` (which an
    /// adapter turns into UnknownTag).
    #[test]
    fn any_other_tag_or_role_is_bad_records() {
        for other in [
            tag::WIRE_PART,
            tag::D_PROTOCOL,
            generic::TEXT,
            generic::FACT,
        ] {
            let out = answer(|w| {
                w.put_text(tag::ALPN, "h2")?;
                w.put(other, &[0; 16])
            });
            assert_eq!(
                decode(&out, ROLE_CLIENT).err(),
                Some(RecErr::Size),
                "{other:#06x}"
            );
        }
        let out = answer(|w| w.put_text(tag::ALPN, "h2"));
        for role in [0, ROLE_DATAGRAM, 4] {
            assert_eq!(decode(&out, role).err(), Some(RecErr::Size), "role {role}");
        }
    }

    /// METRIC is allowed in any OK answer (§3); `decode_metrics` reads it, so the offer decoder passes over it.
    #[test]
    fn metric_records_are_left_to_decode_metrics() {
        let out = answer(|w| {
            w.put_text(tag::ALPN, "h2")?;
            w.put_metric(1, 1, 1.0, &[])?;
            w.put_pair(generic::PAIR, "accept", b"*/*")
        });
        let offer = decode(&out, ROLE_CLIENT).expect("METRIC is not an offer record");
        assert_eq!(alpn(&offer), ["h2"]);
        assert_eq!(defaults(&offer), [("accept", "*/*")]);
    }

    #[test]
    fn a_framing_error_is_returned_as_read() {
        let out = answer(|w| w.put_text(tag::ALPN, "h2"));
        let cut = &out.as_bytes()[..out.len() - 8];
        assert_eq!(
            offer_from(Records::new(cut), ROLE_SERVER).err(),
            Some(RecErr::Truncated)
        );
    }
}
