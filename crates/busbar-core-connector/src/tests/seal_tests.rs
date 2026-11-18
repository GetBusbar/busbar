// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seals: the host's field taken out, each sealed value swapped for filler of its length in

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
fn a_later_broken_filler_never_leaves_an_earlier_credential_in_rejected_wire() {
    let mut seals = Seals::default();
    let mut o = opening(b"first-credential");
    let fields = &mut o.as_mut().unwrap().0;
    fields.push(("x-key".into(), b"second-credential".to_vec()));
    fields.push((SEALED_FIELDS_FIELD.into(), b"x-key".to_vec()));
    seals.seal(&mut o, true, true).unwrap();
    let fields = &o.as_ref().unwrap().0;
    let first = &fields[0].1;
    let second = &fields.iter().find(|(n, _)| n == "x-key").unwrap().1;
    let mut wire = [first.as_slice(), b" ", second, b" ", second].concat();
    assert_eq!(seals.splice(&mut wire), Err(SEAL_BROKEN));
    assert!(!wire
        .windows(b"first-credential".len())
        .any(|w| w == b"first-credential"));
    assert!(
        seals.pending(),
        "rejected output did not consume an earlier seal"
    );
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

#[test]
fn query_pairs_append_in_order_before_fragments_without_becoming_headers() {
    for (target, expected) in [
        ("/path", "/path?key=one%20two&key=&x=%2F%25"),
        ("/path?", "/path?key=one%20two&key=&x=%2F%25"),
        ("/path?old=1", "/path?old=1&key=one%20two&key=&x=%2F%25"),
        (
            "/path?old=1&#frag",
            "/path?old=1&key=one%20two&key=&x=%2F%25#frag",
        ),
    ] {
        for sealing in [false, true] {
            let mut seals = Seals::default();
            let mut o = Some((
                vec![
                    ("busbar-sealed-query".into(), b"key=one%20two".to_vec()),
                    ("x-visible".into(), b"visible".to_vec()),
                    ("busbar-sealed-query".into(), b"key=".to_vec()),
                    ("busbar-sealed-query".into(), b"x=%2F%25".to_vec()),
                ],
                Vec::new().into(),
            ));
            let mut target = target.as_bytes().to_vec();
            assert!(seals
                .seal_queries(0, &mut o, &mut target, sealing, true)
                .unwrap());
            assert_eq!(o.unwrap().0, [("x-visible".into(), b"visible".to_vec())]);
            if sealing {
                assert!(!target
                    .windows(b"one%20two".len())
                    .any(|w| w == b"one%20two"));
                seals.splice(&mut target).unwrap();
            }
            assert_eq!(target, expected.as_bytes());
        }
    }
}

#[test]
fn query_sealing_refuses_cleartext_or_malformed_metadata_without_exposing_values() {
    for (pair, secured, error) in [
        (b"key=secret".as_slice(), false, SEALED_IN_CLEAR),
        (b"key=bad%", true, SEAL_BROKEN),
        (b"key=bad&injected=1", true, SEAL_BROKEN),
    ] {
        let mut seals = Seals::default();
        let mut o = Some((
            vec![("busbar-sealed-query".into(), pair.to_vec())],
            Vec::new().into(),
        ));
        let mut target = b"/path".to_vec();
        assert_eq!(
            seals.seal_queries(0, &mut o, &mut target, true, secured),
            Err(error)
        );
        assert_eq!(target, b"/path");
        assert!(o.unwrap().0.is_empty());
    }
}

#[test]
fn abandoning_one_stream_wipes_only_its_pending_credential() {
    let mut seals = Seals::default();
    let mut first = opening(b"first-pending-credential");
    let mut second = opening(b"second-pending-credential");
    let first_names = take_sealed_names(&mut first.as_mut().unwrap().0);
    let second_names = take_sealed_names(&mut second.as_mut().unwrap().0);
    seals
        .seal_names(1, &mut first, &first_names, true, true)
        .unwrap();
    seals
        .seal_names(3, &mut second, &second_names, true, true)
        .unwrap();
    // The abandoned seal's slot is kept for the connection's next seal (GROUP-records K7, row
    // 57f), so its credential is wiped in place, not at a free: every byte of the slot's storage
    // is zero once the stream is cleared, and the storage is still the slot's.
    let pointer = seals.held[0].value.allocation().as_ptr();
    assert!(seals.held[0]
        .value
        .allocation()
        .windows(b"first-pending-credential".len())
        .any(|w| w == b"first-pending-credential"));
    seals.clear_on(1);
    let slot = seals
        .held
        .iter()
        .find(|s| s.value.allocation().as_ptr() == pointer)
        .expect("the abandoned seal's storage stays with its slot");
    assert!(slot.value.is_empty() && slot.filler.is_empty());
    assert!(
        slot.value.allocation().iter().all(|b| *b == 0),
        "the credential is wiped in place"
    );
    assert!(!seals.pending_on(1));
    assert!(seals.pending_on(3));
    let mut wire = second.unwrap().0[0].1.clone();
    seals.splice(&mut wire).unwrap();
    assert_eq!(wire, b"second-pending-credential");
    assert!(!seals.pending());
}

/// One round on a warm connection: seal an opening, splice it, and clear a second stream's seal.
fn round(seals: &mut Seals, secret: &[u8]) {
    let mut o = opening(secret);
    seals.seal(&mut o, true, true).unwrap();
    let (fields, _) = o.unwrap();
    let mut wire = [b"authorization: ".as_slice(), &fields[0].1, b"\r\n"].concat();
    seals.splice(&mut wire).unwrap();
    assert_eq!(
        wire,
        [b"authorization: ".as_slice(), secret, b"\r\n"].concat()
    );
    let mut other = opening(secret);
    let names = take_sealed_names(&mut other.as_mut().unwrap().0);
    seals.seal_names(7, &mut other, &names, true, true).unwrap();
    assert!(seals.pending_on(7));
    seals.clear_on(7);
    assert!(!seals.pending() && !seals.pending_on(7));
}

#[test]
fn a_warm_connection_reuses_its_seal_slots_and_wipes_what_left() {
    // GROUP-records K7 (row 57f): a spliced or cleared seal is emptied in place, its value wiped,
    // and the connection's next seal is written into the same storage.
    let secret = b"Bearer s3cr3t-value-with-length";
    let mut seals = Seals::default();
    for _ in 0..3 {
        round(&mut seals, secret);
    }
    let slots = seals.held.len();
    let filler_at = seals.held[0].filler.as_ptr();
    let value_cap = seals.held[0].value.capacity();
    for _ in 0..8 {
        round(&mut seals, secret);
    }
    assert_eq!(
        seals.held.len(),
        slots,
        "no slot is made once the connection is warm"
    );
    assert_eq!(
        seals.held[0].filler.as_ptr(),
        filler_at,
        "the filler is refilled in place"
    );
    assert_eq!(
        seals.held[0].value.capacity(),
        value_cap,
        "the value keeps its storage"
    );
    assert!(
        seals
            .held
            .iter()
            .all(|s| s.value.is_empty() && s.filler.is_empty()),
        "every slot that left was emptied: no credential byte stays live in a free slot"
    );
}

#[test]
fn splicing_keeps_the_unspliced_seals_in_their_order() {
    let mut seals = Seals::default();
    let mut o = opening(b"first-credential");
    let fields = &mut o.as_mut().unwrap().0;
    fields.push(("x-key".into(), b"second-credential".to_vec()));
    fields.push(("x-third".into(), b"third-credential".to_vec()));
    fields.push((SEALED_FIELDS_FIELD.into(), b"x-key, x-third".to_vec()));
    seals.seal(&mut o, true, true).unwrap();
    let fields = &o.as_ref().unwrap().0;
    let first = fields[0].1.clone();
    let second = fields.iter().find(|(n, _)| n == "x-key").unwrap().1.clone();
    let third = fields
        .iter()
        .find(|(n, _)| n == "x-third")
        .unwrap()
        .1
        .clone();
    // Only the middle seal's filler is on the wire: it alone is spliced.
    let mut wire = second.clone();
    seals.splice(&mut wire).unwrap();
    assert_eq!(wire, b"second-credential");
    let mut wire = [first.as_slice(), b" ", &third].concat();
    seals.splice(&mut wire).unwrap();
    assert_eq!(wire, b"first-credential third-credential");
    assert!(!seals.pending());
}
