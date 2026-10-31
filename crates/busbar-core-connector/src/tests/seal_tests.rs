// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seals: the host's field taken out, each sealed value swapped for filler of its length in
//! the field-value-safe alphabet, spliced back exactly once, and refused in the clear or when the
//! framer rendered a filler twice.

use super::*;
use busbar_contract::conn::SEALED_FIELDS_FIELD;

fn opening(secret: &[u8]) -> Option<Opening> {
    Some((
        vec![
            ("Authorization".to_owned(), secret.to_vec()),
            ("x-plain".to_owned(), b"visible".to_vec()),
            (SEALED_FIELDS_FIELD.to_owned(), b" authorization ".to_vec()),
        ],
        Vec::new().into(),
    ))
}

#[test]
fn a_sealed_value_becomes_filler_of_its_length_and_splices_back_once() {
    let secret = b"Bearer s3cr3t-value-with-length";
    let mut seals = Seals::default();
    let mut o = opening(secret);
    seals.seal(&mut o, true, true).unwrap();
    let (fields, _) = o.unwrap();
    assert_eq!(fields.len(), 2, "the host's field is taken out");
    let filler = fields[0].1.clone();
    assert_eq!(filler.len(), secret.len());
    assert_ne!(filler, secret.to_vec());
    assert!(filler.iter().all(u8::is_ascii_alphanumeric));
    assert_eq!(fields[1].1, b"visible", "an unnamed field is left alone");
    assert!(seals.pending());
    let mut wire = [b"authorization: ".as_slice(), &filler, b"\r\n"].concat();
    seals.splice(&mut wire).unwrap();
    assert_eq!(
        wire,
        [b"authorization: ".as_slice(), secret, b"\r\n"].concat()
    );
    assert!(!seals.pending(), "spliced once, done");
}

#[test]
fn a_filler_rendered_twice_is_refused() {
    let mut seals = Seals::default();
    let mut o = opening(b"Bearer another-secret-value");
    seals.seal(&mut o, true, true).unwrap();
    let filler = o.unwrap().0[0].1.clone();
    let mut wire = [filler.as_slice(), b" ", &filler].concat();
    assert_eq!(seals.splice(&mut wire), Err(SEAL_BROKEN));
    assert!(!wire.windows(6).any(|w| w == b"Bearer"), "nothing spliced");
}

#[test]
fn a_sealed_value_in_the_clear_is_refused_and_an_unsealing_framer_is_handed_it() {
    let mut seals = Seals::default();
    let mut o = opening(b"Bearer clear-text-secret");
    assert_eq!(seals.seal(&mut o, true, false), Err(SEALED_IN_CLEAR));
    let mut o = opening(b"Bearer clear-text-secret");
    seals.seal(&mut o, false, true).unwrap();
    let (fields, _) = o.unwrap();
    assert_eq!(
        fields.len(),
        2,
        "the host's field is taken out whatever the framer"
    );
    assert_eq!(fields[0].1, b"Bearer clear-text-secret");
    assert!(!seals.pending());
}
