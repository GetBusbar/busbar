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
