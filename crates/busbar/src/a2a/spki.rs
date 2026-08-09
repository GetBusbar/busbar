// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT-LAYER IDENTITY: a peer certificate's SubjectPublicKeyInfo, hashed.
//!
//! An A2A card's signature is OPTIONAL. Where a vendor does not sign, the only authenticity root
//! left is the one the network already established: the certificate the card endpoint proved it
//! held the private key for. Pinning the SPKI rather than the whole certificate is the standard
//! choice and it is the right one here — a certificate is re-issued on every renewal and its bytes
//! change each time, while the key underneath it survives a renewal. A pin on the certificate would
//! demand a re-approval every ninety days, and a pin an operator has to clear that often is a pin
//! they will learn to clear without reading.
//!
//! ## WHERE THE CERTIFICATE COMES FROM, and why this does not weaken anything
//!
//! The DER handed to [`spki_pin`] is the leaf certificate of a handshake that ALREADY COMPLETED
//! under the ordinary chain-and-name check ([`super::transport`]). This module is therefore an
//! OBSERVATION of a connection somebody else already verified, never a substitute for verifying
//! one. That ordering is the whole safety argument: there is no path here that produces a pin from
//! a handshake that was not verified, because a handshake that was not verified produces no
//! response to read a certificate off.
//!
//! ## Why a DER walk rather than an X.509 crate
//!
//! The question this file answers is small and completely determined by RFC 5280: the SPKI is the
//! seventh member of `TBSCertificate`, and `TBSCertificate` is the first member of `Certificate`.
//! Walking to it is a length-prefixed skip, and NOTHING here interprets the fields it walks past —
//! it does not parse a name, a validity window, an extension or a key. Those are the parts of X.509
//! that are hard and that a dedicated crate earns its place doing, and every one of them has
//! already been done by the TLS stack before this code sees a byte.
//!
//! ## The encoding is DER, and a non-DER encoding is a REFUSAL
//!
//! BER's indefinite lengths, non-minimal length forms and leading length padding all give one
//! certificate several encodings. A pin computed over a re-encodable document is a pin an upstream
//! can change without changing the key, so every one of those forms is refused rather than
//! tolerated. TLS requires DER, so a peer that sends anything else has a problem this code should
//! not be papering over.

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Standard base64 (padded), matching the rendering of every other digest on this plane.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// How many `TBSCertificate` members sit between the optional version and the SPKI:
/// `serialNumber`, `signature`, `issuer`, `validity`, `subject`. RFC 5280 section 4.1.
const MEMBERS_BEFORE_SPKI: usize = 5;

/// ASN.1 `SEQUENCE`, constructed. The only tag this walk expects to find at a structural position.
const TAG_SEQUENCE: u8 = 0x30;

/// `[0] EXPLICIT`, the context tag that carries `TBSCertificate.version`. Optional (absent means
/// v1), so its presence is tested rather than assumed.
const TAG_VERSION: u8 = 0xA0;

/// Why a peer certificate produced no pin. Every arm is a refusal; there is no arm meaning "could
/// not read it, assume it matches".
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SpkiError {
    /// The bytes ran out mid-element.
    Truncated,
    /// A tag that is not what RFC 5280 puts at this position.
    UnexpectedTag { want: u8, got: u8 },
    /// An indefinite length, a non-minimal length, or a length wider than any certificate needs.
    /// All three are legal BER and none of them is DER, and each gives one certificate a second
    /// encoding — which is a second pin for one key.
    NotDer(&'static str),
}

impl std::fmt::Display for SpkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpkiError::Truncated => write!(
                f,
                "the peer certificate ends part-way through an element, so there is no \
                 subject-public-key-info in it to pin"
            ),
            SpkiError::UnexpectedTag { want, got } => write!(
                f,
                "the peer certificate has ASN.1 tag {got:#04x} where RFC 5280 puts {want:#04x}"
            ),
            SpkiError::NotDer(why) => write!(
                f,
                "the peer certificate is not DER-encoded ({why}); a certificate with more than one \
                 encoding has more than one pin for one key"
            ),
        }
    }
}

/// One ASN.1 element, as the walk sees it.
struct Element<'a> {
    tag: u8,
    /// The element's CONTENTS, without its tag and length.
    contents: &'a [u8],
    /// The element WHOLE, tag and length included. This is what a pin is taken over: the SPKI's
    /// standard rendering includes its own header, and hashing the contents alone would produce a
    /// value that no other tool computes.
    whole: &'a [u8],
}

/// Read exactly one DER element off the front of `buf`.
fn element(buf: &[u8]) -> Result<Element<'_>, SpkiError> {
    let (&tag, rest) = buf.split_first().ok_or(SpkiError::Truncated)?;
    let (&first_len, rest) = rest.split_first().ok_or(SpkiError::Truncated)?;

    let (len, header) = if first_len < 0x80 {
        // Short form: the length IS the byte.
        (usize::from(first_len), 2usize)
    } else if first_len == 0x80 {
        return Err(SpkiError::NotDer("an indefinite length"));
    } else {
        let count = usize::from(first_len & 0x7f);
        if count > 4 {
            return Err(SpkiError::NotDer("a length wider than four octets"));
        }
        let bytes = rest.get(..count).ok_or(SpkiError::Truncated)?;
        // DER's minimality rule, both halves: a leading zero octet, and a long form used where the
        // short form would have fit. Either one is a second spelling of one length.
        if bytes.first() == Some(&0) {
            return Err(SpkiError::NotDer("a length with a leading zero octet"));
        }
        let mut len = 0usize;
        for b in bytes {
            len = (len << 8) | usize::from(*b);
        }
        if len < 0x80 {
            return Err(SpkiError::NotDer(
                "a long-form length that the short form would have carried",
            ));
        }
        (len, 2 + count)
    };

    let end = header.checked_add(len).ok_or(SpkiError::Truncated)?;
    let whole = buf.get(..end).ok_or(SpkiError::Truncated)?;
    Ok(Element {
        tag,
        contents: &whole[header..],
        whole,
    })
}

/// Read one element and hand back the bytes that follow it.
fn skip(buf: &[u8]) -> Result<&[u8], SpkiError> {
    let e = element(buf)?;
    Ok(&buf[e.whole.len()..])
}

fn expect_sequence(buf: &[u8]) -> Result<Element<'_>, SpkiError> {
    let e = element(buf)?;
    if e.tag != TAG_SEQUENCE {
        return Err(SpkiError::UnexpectedTag {
            want: TAG_SEQUENCE,
            got: e.tag,
        });
    }
    Ok(e)
}

/// THE SubjectPublicKeyInfo of a DER X.509 certificate, whole (tag and length included).
///
/// The walk is RFC 5280 section 4.1 read literally: `Certificate ::= SEQUENCE { tbsCertificate,
/// signatureAlgorithm, signature }` and `TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1,
/// serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, … }`.
pub(crate) fn subject_public_key_info(cert_der: &[u8]) -> Result<&[u8], SpkiError> {
    let certificate = expect_sequence(cert_der)?;
    let tbs = expect_sequence(certificate.contents)?;

    let mut rest = tbs.contents;
    // `version` is `[0] EXPLICIT … DEFAULT v1`, so it is ABSENT on a v1 certificate. Testing for
    // the tag rather than assuming it is present is the difference between reading the SPKI and
    // reading the member before it.
    if rest.first() == Some(&TAG_VERSION) {
        rest = skip(rest)?;
    }
    for _ in 0..MEMBERS_BEFORE_SPKI {
        rest = skip(rest)?;
    }
    // The SPKI is itself a SEQUENCE; checking that is a cheap assertion that the walk landed where
    // it meant to rather than in the middle of something.
    Ok(expect_sequence(rest)?.whole)
}

/// THE PIN: `sha256/<base64>` over the peer certificate's whole SubjectPublicKeyInfo.
///
/// The same rendering [`super::card::sha256_tagged`] gives every other digest on this plane, so an
/// operator comparing a configured pin against an audit row is comparing one spelling. It is also
/// the spelling `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256
/// -binary | base64` produces, which is how an operator obtains the value to configure in the first
/// place — a pin nobody can compute out of band is not an out-of-band root.
pub(crate) fn spki_pin(cert_der: &[u8]) -> Result<String, SpkiError> {
    let spki = subject_public_key_info(cert_der)?;
    Ok(format!("sha256/{}", B64.encode(Sha256::digest(spki))))
}

#[cfg(test)]
#[path = "tests/spki_tests.rs"]
mod spki_tests;
