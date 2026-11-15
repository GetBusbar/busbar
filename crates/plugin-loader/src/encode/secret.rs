// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Secret request encoders and describe decoders (IF §8.8). W1-A6.

use busbar_plugin_abi::records::{Full, RecErr, Records, Writer};

use crate::ports::secret::SugarDecl;

pub fn encode_reference(w: &mut impl Writer, settings_json: &[u8]) -> Result<(), Full> {
    let _ = (w, settings_json);
    todo!()
}

/// Round 6: every D_SUGAR item of one describe answer (validated: word grammar, four TEXT, known role).
pub fn decode_sugars(describe: Records<'_>) -> Result<Vec<SugarDecl>, RecErr> {
    let _ = describe;
    todo!()
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
