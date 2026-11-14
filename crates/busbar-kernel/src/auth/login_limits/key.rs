// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCOUNT KEY AND THE LOGIN-STATE KEY, both derived from the signing key.
//!
//! The account key is `HMAC(HKDF(signing key, "busbar login-attempts v1"), NFKC_Casefold(name))`:
//! usernames are never stored or logged in clear, and every node that resolves the same signing key
//! computes the same key, so a shared core store holds one budget per account for the whole fleet.
//! There is NO boot-random fallback for it: without a signing key the submission is refused
//! (`login-limiter-no-key`), because per-node keys over a shared store would split the budget
//! silently.

use busbar_contract::crypto::HmacSha256Key;
use unicode_normalization::UnicodeNormalization;

/// The HKDF label of the account key.
pub const ACCOUNT_LABEL: &[u8] = b"busbar login-attempts v1";

/// The HKDF label of the login-state cookie's MAC key.
pub const STATE_LABEL: &[u8] = b"busbar login-state v1";

/// How many hex characters of the account HMAC name a record (128 bits).
const FINGERPRINT_HEX: usize = 32;

/// The key account fingerprints are computed under. No `Debug` of the key, no `Clone`.
pub struct AccountKeyer(HmacSha256Key);

impl std::fmt::Debug for AccountKeyer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKeyer(..)")
    }
}

impl AccountKeyer {
    /// Derive from the node's signing-key material.
    #[must_use]
    pub fn derive(material: &[u8]) -> Self {
        Self(busbar_kernel_identity::caller_ref::derive_hmac_key(
            material,
            ACCOUNT_LABEL,
        ))
    }

    /// The fingerprint of the account a submitted identifier names: 32 lowercase hex characters of
    /// the HMAC over its normalised form ([`normalise_account`]).
    #[must_use]
    pub fn fingerprint(&self, submitted: &str) -> String {
        let normalised = normalise_account(submitted);
        let tag = self.0.sign(normalised.as_bytes());
        let mut hex = hex::encode(tag);
        hex.truncate(FINGERPRINT_HEX);
        hex
    }
}

/// The MAC key of the login-state cookie.
pub struct StateKey(HmacSha256Key);

impl std::fmt::Debug for StateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StateKey(..)")
    }
}

impl StateKey {
    /// Derive from the node's signing-key material.
    #[must_use]
    pub fn derive(material: &[u8]) -> Self {
        Self(busbar_kernel_identity::caller_ref::derive_hmac_key(
            material,
            STATE_LABEL,
        ))
    }

    /// The tag over `payload`.
    #[must_use]
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.0.sign(payload).to_vec()
    }

    /// Whether `tag` is the tag over `payload` (constant time).
    #[must_use]
    pub fn verify(&self, payload: &[u8], tag: &[u8]) -> bool {
        self.0.verify(payload, tag).is_ok()
    }
}

/// THE ACCOUNT NORMALISATION: NFKC_Casefold (default-ignorable code points dropped, compatibility
/// and width folded, full case folding), then whitespace trimmed and collapsed, then one `DOMAIN\`
/// prefix and one `@suffix` stripped. `Alice`, `ＡＬＩＣＥ`, `CORP\alice`, `alice@corp.example` and
/// `al\u{200B}ice` are one account. Over-merging (`CORP\alice` with `EMEA\alice`) only makes that
/// bucket stricter, inside busbar; it is accepted and documented.
#[must_use]
pub fn normalise_account(raw: &str) -> String {
    let folded = nfkc_casefold(raw);
    let collapsed = folded.split_whitespace().collect::<Vec<_>>().join(" ");
    let without_domain = match collapsed.split_once('\\') {
        Some((_, rest)) => rest,
        None => collapsed.as_str(),
    };
    let account = match without_domain.rsplit_once('@') {
        Some((name, _)) => name,
        None => without_domain,
    };
    account.trim().to_string()
}

/// `NFKC_Casefold` (UAX #44): drop default-ignorable code points, NFKC, full case fold, NFKC.
fn nfkc_casefold(raw: &str) -> String {
    let kept: String = raw.chars().filter(|c| !is_default_ignorable(*c)).collect();
    let mut folded = String::with_capacity(kept.len());
    for c in kept.nfkc() {
        full_case_fold(c, &mut folded);
    }
    folded
        .nfkc()
        .filter(|c| !is_default_ignorable(*c))
        .collect()
}

/// Full case folding (`CaseFolding.txt` status C + F): lower-casing, except where the fold differs
/// from the lower-case mapping.
fn full_case_fold(c: char, out: &mut String) {
    let special: Option<&str> = match c {
        '\u{00DF}' | '\u{1E9E}' => Some("ss"),
        '\u{03C2}' => Some("\u{03C3}"),
        '\u{017F}' => Some("s"),
        '\u{0345}' | '\u{1FBE}' => Some("\u{03B9}"),
        '\u{03D0}' => Some("\u{03B2}"),
        '\u{03D1}' => Some("\u{03B8}"),
        '\u{03D5}' => Some("\u{03C6}"),
        '\u{03D6}' => Some("\u{03C0}"),
        '\u{03F0}' => Some("\u{03BA}"),
        '\u{03F1}' => Some("\u{03C1}"),
        '\u{03F5}' => Some("\u{03B5}"),
        '\u{1E9B}' => Some("\u{1E61}"),
        '\u{0130}' => Some("i\u{0307}"),
        '\u{0149}' => Some("\u{02BC}n"),
        '\u{01F0}' => Some("j\u{030C}"),
        '\u{0390}' => Some("\u{03B9}\u{0308}\u{0301}"),
        '\u{03B0}' => Some("\u{03C5}\u{0308}\u{0301}"),
        '\u{0587}' => Some("\u{0565}\u{0582}"),
        '\u{FB00}' => Some("ff"),
        '\u{FB01}' => Some("fi"),
        '\u{FB02}' => Some("fl"),
        '\u{FB03}' => Some("ffi"),
        '\u{FB04}' => Some("ffl"),
        '\u{FB05}' | '\u{FB06}' => Some("st"),
        // Cherokee folds to its UPPER case (the only script that does).
        '\u{AB70}'..='\u{ABBF}' => {
            let upper = char::from_u32(c as u32 - 0xAB70 + 0x13A0).unwrap_or(c);
            out.push(upper);
            return;
        }
        '\u{13F8}'..='\u{13FD}' => {
            let upper = char::from_u32(c as u32 - 8).unwrap_or(c);
            out.push(upper);
            return;
        }
        '\u{13A0}'..='\u{13F5}' => {
            out.push(c);
            return;
        }
        _ => None,
    };
    match special {
        Some(s) => out.push_str(s),
        None => out.extend(c.to_lowercase()),
    }
}

/// `Default_Ignorable_Code_Point` (DerivedCoreProperties.txt).
fn is_default_ignorable(c: char) -> bool {
    matches!(c as u32,
        0x00AD
        | 0x034F
        | 0x061C
        | 0x115F..=0x1160
        | 0x17B4..=0x17B5
        | 0x180B..=0x180F
        | 0x200B..=0x200F
        | 0x202A..=0x202E
        | 0x2060..=0x206F
        | 0x3164
        | 0xFE00..=0xFE0F
        | 0xFEFF
        | 0xFFA0
        | 0xFFF0..=0xFFF8
        | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A
        | 0xE0000..=0xE0FFF)
}
