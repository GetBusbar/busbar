// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Secret request encoders and describe decoders (IF §8.8). W1-A6.

use std::sync::Arc;

use busbar_plugin_abi::records::{Full, RecErr, Records, Writer, tag};
use busbar_plugin_abi::secret;

use crate::ports::secret::SugarDecl;

/// At most this many D_SUGAR items per plugin (IF §8.2).
const SUGARS_MAX: usize = 4;
/// A shorthand word is `[a-z][a-z0-9_-]{0,31}` (IF §8.2).
const WORD_MAX: usize = 32;
/// The SugarRec ahead of a D_SUGAR item's four TEXT records: `role: u32, flags: u32`.
const SUGAR_REC: usize = 8;

/// The `resolve` request: the reference's `settings` object, verbatim, as the one CONFIG record (IF §8.2).
pub fn encode_reference(w: &mut impl Writer, settings_json: &[u8]) -> Result<(), Full> {
    w.put(tag::CONFIG, settings_json)
}

/// Round 6: every D_SUGAR item of one describe answer (validated: word grammar, four TEXT, known role).
///
/// Every other describe item is skipped. The declaring plugin's identity is not in the describe bytes, so each
/// `SugarDecl` carries an empty one; the registry (`Registry::add`) tags it with the verified stamp name.
/// Errors: more than four items, a short or odd body, an unknown role or a bad word or a wrong TEXT count is
/// `Size`; an unknown flag bit is `Reserved`; a non-TEXT record in the tail is `Unknown(tag)`; bad UTF-8 is `Utf8`.
pub fn decode_sugars(describe: Records<'_>) -> Result<Vec<SugarDecl>, RecErr> {
    let mut out = Vec::new();
    for rec in describe {
        let rec = rec?;
        if rec.tag != secret::tag::D_SUGAR {
            continue;
        }
        if out.len() == SUGARS_MAX {
            return Err(RecErr::Size);
        }
        out.push(decode_one(rec.body)?);
    }
    Ok(out)
}

fn decode_one(body: &[u8]) -> Result<SugarDecl, RecErr> {
    let (head, tail) = body.split_at_checked(SUGAR_REC).ok_or(RecErr::Size)?;
    let role = u32::from_ne_bytes([head[0], head[1], head[2], head[3]]);
    let flags = u32::from_ne_bytes([head[4], head[5], head[6], head[7]]);
    if role > secret::SUGAR_ROLE_PATH {
        return Err(RecErr::Size);
    }
    if flags & !secret::SUGAR_ALIAS != 0 {
        return Err(RecErr::Reserved);
    }
    let mut texts = [""; 4];
    let mut n = 0;
    for rec in Records::new(tail) {
        let rec = rec?;
        if rec.tag != tag::TEXT {
            return Err(RecErr::Unknown(rec.tag));
        }
        *texts.get_mut(n).ok_or(RecErr::Size)? = rec.text()?;
        n += 1;
    }
    if n != texts.len() {
        return Err(RecErr::Size);
    }
    let [word, key, shown, names] = texts;
    if !word_ok(word) {
        return Err(RecErr::Size);
    }
    Ok(SugarDecl {
        identity: Arc::from(""),
        role,
        alias: flags & secret::SUGAR_ALIAS != 0,
        word: word.into(),
        key: key.into(),
        shown: shown.into(),
        names: names.into(),
    })
}

fn word_ok(word: &str) -> bool {
    let b = word.as_bytes();
    b.len() <= WORD_MAX
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::records::{Reply, tag as generic};
    use busbar_plugin_abi::secret::{SUGAR_ALIAS, SUGAR_ROLE_FILL, SUGAR_ROLE_PATH, tag};

    /// A D_SUGAR record as `abi::secret::sugar` writes it: SugarRec, then the texts as TEXT records.
    fn item(role: u32, flags: u32, texts: &[&str]) -> Reply {
        let mut tail = Reply::new();
        for t in texts {
            tail.put_text(generic::TEXT, t).unwrap();
        }
        let mut body = Vec::new();
        body.extend_from_slice(&role.to_ne_bytes());
        body.extend_from_slice(&flags.to_ne_bytes());
        body.extend_from_slice(tail.as_bytes());
        let mut r = Reply::new();
        r.put(tag::D_SUGAR, &body).unwrap();
        r
    }

    fn good(word: &str) -> Reply {
        item(
            SUGAR_ROLE_FILL,
            SUGAR_ALIAS,
            &[word, "key", "VAR", "the variable"],
        )
    }

    #[test]
    fn a_reference_is_one_config_record_holding_the_settings_verbatim() {
        let mut w = Reply::new();
        encode_reference(&mut w, br#"{"name":"db"}"#).unwrap();
        let mut recs = Records::new(w.as_bytes());
        let r = recs.next_rec().unwrap().unwrap();
        assert_eq!(r.tag, generic::CONFIG);
        assert_eq!(r.body, br#"{"name":"db"}"#);
        assert!(recs.next_rec().is_none());
    }

    #[test]
    fn a_describe_answer_without_sugar_declares_none() {
        let mut r = Reply::new();
        r.put(tag::D_REF_SCHEMA, b"{}").unwrap();
        assert!(
            decode_sugars(Records::new(r.as_bytes()))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_sugar_item_decodes_to_its_declaration() {
        let mut r = Reply::new();
        r.put(tag::D_REF_SCHEMA, b"{}").unwrap();
        r.put(
            tag::D_SUGAR,
            &item_body(SUGAR_ROLE_PATH, 0, &["file", "path", "", "the file"]),
        )
        .unwrap();
        let s = decode_sugars(Records::new(r.as_bytes())).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].role, SUGAR_ROLE_PATH);
        assert!(!s[0].alias);
        assert_eq!(&*s[0].word, "file");
        assert_eq!(&*s[0].key, "path");
        assert_eq!(&*s[0].shown, "");
        assert_eq!(&*s[0].names, "the file");
    }

    fn item_body(role: u32, flags: u32, texts: &[&str]) -> Vec<u8> {
        let whole = item(role, flags, texts);
        // Strip the D_SUGAR record head (8 bytes) and the padding back to the body.
        let len = u32::from_ne_bytes(whole.as_bytes()[4..8].try_into().unwrap()) as usize;
        whole.as_bytes()[8..8 + len].to_vec()
    }

    #[test]
    fn the_alias_flag_is_read() {
        let r = good("env");
        let s = decode_sugars(Records::new(r.as_bytes())).unwrap();
        assert!(s[0].alias);
        assert_eq!(s[0].role, SUGAR_ROLE_FILL);
    }

    #[test]
    fn at_most_four_items_per_plugin() {
        let mut r = Reply::new();
        for w in ["a", "b", "c", "d"] {
            r.put(tag::D_SUGAR, &item_body(0, 0, &[w, "k", "", "n"]))
                .unwrap();
        }
        assert_eq!(decode_sugars(Records::new(r.as_bytes())).unwrap().len(), 4);
        r.put(tag::D_SUGAR, &item_body(0, 0, &["e", "k", "", "n"]))
            .unwrap();
        assert!(matches!(
            decode_sugars(Records::new(r.as_bytes())),
            Err(RecErr::Size)
        ));
    }

    #[test]
    fn a_bad_word_a_bad_role_or_a_wrong_text_count_is_refused() {
        let bad_words = ["", "Env", "1env", "e v", "a".repeat(33).leak() as &str];
        for w in bad_words {
            let r = good(w);
            assert!(
                matches!(decode_sugars(Records::new(r.as_bytes())), Err(RecErr::Size)),
                "word {w:?}"
            );
        }
        let ok = good(&"a".repeat(32));
        assert!(decode_sugars(Records::new(ok.as_bytes())).is_ok());
        let role = item(3, 0, &["env", "k", "", "n"]);
        assert!(matches!(
            decode_sugars(Records::new(role.as_bytes())),
            Err(RecErr::Size)
        ));
        let few = item(0, 0, &["env", "k", ""]);
        assert!(matches!(
            decode_sugars(Records::new(few.as_bytes())),
            Err(RecErr::Size)
        ));
        let many = item(0, 0, &["env", "k", "", "n", "x"]);
        assert!(matches!(
            decode_sugars(Records::new(many.as_bytes())),
            Err(RecErr::Size)
        ));
        let short = {
            let mut r = Reply::new();
            r.put(tag::D_SUGAR, &[0, 0, 0, 0]).unwrap();
            r
        };
        assert!(matches!(
            decode_sugars(Records::new(short.as_bytes())),
            Err(RecErr::Size)
        ));
    }

    #[test]
    fn unknown_flag_bits_and_non_text_tails_are_refused() {
        let flags = item(0, 2, &["env", "k", "", "n"]);
        assert!(matches!(
            decode_sugars(Records::new(flags.as_bytes())),
            Err(RecErr::Reserved)
        ));
        let mut tail = Reply::new();
        for t in ["env", "k", ""] {
            tail.put_text(generic::TEXT, t).unwrap();
        }
        tail.put(generic::FAIL, b"n").unwrap();
        let mut body = vec![0u8; 8];
        body.extend_from_slice(tail.as_bytes());
        let mut r = Reply::new();
        r.put(tag::D_SUGAR, &body).unwrap();
        assert!(matches!(
            decode_sugars(Records::new(r.as_bytes())),
            Err(RecErr::Unknown(t)) if t == generic::FAIL
        ));
    }

    #[test]
    fn non_utf8_text_is_refused() {
        let mut tail = Reply::new();
        tail.put(generic::TEXT, &[0xff]).unwrap();
        let mut body = vec![0u8; 8];
        body.extend_from_slice(tail.as_bytes());
        let mut r = Reply::new();
        r.put(tag::D_SUGAR, &body).unwrap();
        assert!(matches!(
            decode_sugars(Records::new(r.as_bytes())),
            Err(RecErr::Utf8)
        ));
    }
}
