// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KEY PIN'S ONE READER: the documented `sha256/<base64>` spelling is canonical, plain base64 is
//! its alias, and anything that names no SHA-256 digest is refused.

use super::{canonical_key_pin, key_pin, BadKeyPin, KEY_PIN_TAG};

/// A SubjectPublicKeyInfo stand-in: the reader never looks inside it, only at its digest.
const SPKI: &[u8] = b"a subject public key info";

/// RED: the canonical spelling is the documented one, and both written spellings read to it. The
/// observed pin was plain base64, so the documented `sha256/` form never matched it.
#[test]
fn red_both_spellings_read_to_the_documented_sha256_form() {
    let observed = key_pin(SPKI);
    assert!(observed.starts_with(KEY_PIN_TAG), "{observed}");
    let plain = observed.strip_prefix(KEY_PIN_TAG).expect("tagged");
    assert_eq!(
        canonical_key_pin(&observed).as_deref(),
        Ok(observed.as_str())
    );
    assert_eq!(canonical_key_pin(plain).as_deref(), Ok(observed.as_str()));
    assert_eq!(
        canonical_key_pin(&format!("  {observed}\n")).as_deref(),
        Ok(observed.as_str()),
        "surrounding whitespace is no part of the pin"
    );
}

/// The spelling is the digest's: SHA-256 over the whole SubjectPublicKeyInfo, standard base64 with
/// padding, checked against an independent encoder.
#[test]
fn the_pin_is_the_sha256_of_the_key_info_in_standard_base64() {
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(SPKI);
    assert_eq!(
        key_pin(SPKI),
        format!(
            "sha256/{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        )
    );
}

/// A pin that names no SHA-256 digest is refused, in either spelling: empty, another tag, not
/// base64, unpadded, or a digest of another length.
#[test]
fn a_pin_that_names_no_sha256_digest_is_refused() {
    let observed = key_pin(SPKI);
    let plain = observed.strip_prefix(KEY_PIN_TAG).expect("tagged");
    let unpadded = plain.trim_end_matches('=');
    let short = crate::media::base64_encode(&[7_u8; 20]);
    for bad in [
        String::new(),
        "   ".to_string(),
        KEY_PIN_TAG.to_string(),
        format!("sha1/{plain}"),
        format!("SHA256/{plain}"),
        "sha256/not base64!".to_string(),
        unpadded.to_string(),
        format!("{KEY_PIN_TAG}{unpadded}"),
        short.clone(),
        format!("{KEY_PIN_TAG}{short}"),
    ] {
        assert!(
            matches!(canonical_key_pin(&bad), Err(BadKeyPin(_))),
            "{bad:?} must be refused"
        );
    }
}

/// RED: a PLAIN alias whose own base64 begins `sha256/` (`/` is a base64 digit) is read as that
/// alias, by what decodes, never by the prefix alone. Thirty-two bytes are 44 base64 characters
/// (43 digits, the 43rd carrying 4 bits and 2 zero bits, and one `=`), so `sha256/` + 36 `A` + `=`
/// is 44 characters decoding to exactly 32 bytes; the 37-character tail after `sha256/` is no
/// padded base64 (37 is not a multiple of 4). Read by its prefix, it was refused.
#[test]
fn red_a_plain_alias_that_begins_like_the_tag_reads_as_the_alias() {
    use base64::Engine as _;
    let plain = format!("{KEY_PIN_TAG}{}=", "A".repeat(36));
    assert_eq!(plain.len(), 44);
    let digest = base64::engine::general_purpose::STANDARD
        .decode(&plain)
        .expect("a plain alias of 32 bytes");
    assert_eq!(digest.len(), 32);
    assert!(
        base64::engine::general_purpose::STANDARD
            .decode(plain.strip_prefix(KEY_PIN_TAG).expect("tagged"))
            .is_err(),
        "its tail is no padded base64"
    );
    assert_eq!(
        canonical_key_pin(&plain).as_deref(),
        Ok(format!("{KEY_PIN_TAG}{plain}").as_str())
    );
}

/// RED: a tagged value is canonical only where its tail decodes to EXACTLY one SHA-256 digest; a
/// tail of 31 or 33 bytes is refused (and is no plain alias either).
#[test]
fn red_a_tagged_value_of_31_or_33_bytes_is_refused() {
    for n in [31_usize, 33] {
        let tail = crate::media::base64_encode(&vec![7_u8; n]);
        let written = format!("{KEY_PIN_TAG}{tail}");
        assert!(
            matches!(canonical_key_pin(&written), Err(BadKeyPin(_))),
            "{n} bytes: {written}"
        );
    }
}

/// The tagged spelling is the contract's ONE tagged-digest renderer's: the key pin of a key info is
/// its document digest, byte for byte.
#[test]
fn the_key_pin_is_the_one_tagged_digest() {
    assert_eq!(key_pin(SPKI), crate::abi::sdk::digest::sha256_tagged(SPKI));
}
