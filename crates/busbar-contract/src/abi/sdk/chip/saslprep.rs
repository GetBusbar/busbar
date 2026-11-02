// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SASLprep with guarded owned character buffers. The Unicode primitives only

use stringprep::tables;
use unicode_normalization::char::{canonical_combining_class, compose, decompose_compatible};
use zeroize::{Zeroize, Zeroizing};

/// `None` preserves the original bytes, as PostgreSQL requires on preparation failure.
pub(super) fn password(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut chars = Zeroizing::new(Vec::new());
    for c in text.chars() {
        let c = if tables::non_ascii_space_character(c) {
            ' '
        } else {
            c
        };
        if tables::commonly_mapped_to_nothing(c) {
            continue;
        }

        if tables::unassigned_code_point(c) {
            return None;
        }
        decompose_compatible(unicode_3_2_decomposition(c), |d| push_wiping(&mut chars, d));
    }
    if chars.is_empty() {
        return None;
    }

    for i in 1..chars.len() {
        let class = canonical_combining_class(chars[i]);
        if class == 0 {
            continue;
        }
        let mut j = i;
        while j > 0 && canonical_combining_class(chars[j - 1]) > class {
            chars.swap(j - 1, j);
            j -= 1;
        }
    }

    let mut starter = None;
    let mut last_class = 0;
    let mut written = 0;
    for read in 0..chars.len() {
        let c = chars[read];
        let class = canonical_combining_class(c);
        if let Some(at) = starter {
            if last_class == 0 || last_class < class {
                if let Some(composed) = compose(chars[at], c) {
                    chars[at] = composed;
                    continue;
                }
            }
        }
        chars[written] = c;
        if class == 0 {
            starter = Some(written);
        }
        last_class = class;
        written += 1;
    }
    chars[written..].zeroize();
    chars.truncate(written);
    if chars.iter().copied().any(prohibited) {
        return None;
    }
    if chars.iter().copied().any(tables::bidi_r_or_al)
        && (chars.iter().copied().any(unicode_3_2_bidi_l)
            || !chars.first().copied().is_some_and(tables::bidi_r_or_al)
            || !chars.last().copied().is_some_and(tables::bidi_r_or_al))
    {
        return None;
    }
    if chars.iter().copied().any(tables::unassigned_code_point) {
        return None;
    }

    let len = chars
        .iter()
        .try_fold(0_usize, |n, c| n.checked_add(c.len_utf8()))?;
    let mut out = Zeroizing::new(String::with_capacity(len));
    for &c in chars.iter() {
        out.push(c);
    }
    Some(out)
}

fn push_wiping(chars: &mut Zeroizing<Vec<char>>, c: char) {
    if chars.len() == chars.capacity() {
        let mut next = Zeroizing::new(Vec::with_capacity(chars.len().saturating_mul(2).max(4)));
        next.extend_from_slice(chars);
        *chars = next;
    }
    chars.push(c);
}

fn prohibited(c: char) -> bool {
    tables::non_ascii_space_character(c)
        || tables::ascii_control_character(c)
        || tables::non_ascii_control_character(c)
        || tables::private_use(c)
        || tables::non_character_code_point(c)
        || tables::surrogate_code(c)
        || tables::inappropriate_for_plain_text(c)
        || tables::inappropriate_for_canonical_representation(c)
        || tables::change_display_properties_or_deprecated(c)
        || tables::tagging_character(c)
}

fn unicode_3_2_decomposition(c: char) -> char {
    match c {
        '\u{2f868}' => '\u{2136a}',
        '\u{2f874}' => '\u{5f33}',
        '\u{2f91f}' => '\u{43ab}',
        '\u{2f95f}' => '\u{7aae}',
        '\u{2f9bf}' => '\u{4d57}',
        _ => c,
    }
}

fn unicode_3_2_bidi_l(c: char) -> bool {
    match c {
        '\u{0cbf}'
        | '\u{0cc6}'
        | '\u{1734}'
        | '\u{2132}'
        | '\u{2800}'..='\u{28ff}'
        | '\u{302e}'..='\u{302f}' => false,
        '\u{17b4}'..='\u{17b5}'
        | '\u{1885}'..='\u{1886}'
        | '\u{1d6c1}'
        | '\u{1d6db}'
        | '\u{1d6fb}'
        | '\u{1d715}'
        | '\u{1d735}'
        | '\u{1d74f}'
        | '\u{1d76f}'
        | '\u{1d789}'
        | '\u{1d7a9}'
        | '\u{1d7c3}' => true,
        _ => tables::bidi_l(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_normalization_preserves_order_blocking_hangul_and_exclusions() {
        for (input, expected) in [
            ("I\u{00ad}X", "IX"),
            ("\u{2168}", "IX"),
            ("\u{00aa}", "a"),
            ("\u{1100}\u{1161}\u{11a8}", "\u{ac01}"),
            ("\u{ac01}", "\u{ac01}"),
            ("\u{0315}\u{0300}", "\u{0300}\u{0315}"),
            ("A\u{0305}\u{0300}", "A\u{0305}\u{0300}"),
            ("A\u{0315}\u{0300}", "\u{00c0}\u{0315}"),
            ("A\u{030a}\u{0301}", "\u{01fa}"),
            ("A\u{0301}\u{0327}", "\u{00c1}\u{0327}"),
            ("\u{0344}", "\u{0308}\u{0301}"),
        ] {
            let prepared = password(input.as_bytes()).expect("valid SASLprep");
            assert_eq!(prepared.as_str(), expected);
            fn guarded<T: zeroize::ZeroizeOnDrop>(_: &T) {}
            guarded(&prepared);
        }
    }

    #[test]
    fn guarded_growth_preserves_long_combining_sequences() {
        let input = format!("A{}\u{0300}", "\u{0315}".repeat(64));
        let expected = format!("\u{00c0}{}", "\u{0315}".repeat(64));
        assert_eq!(password(input.as_bytes()).unwrap().as_str(), expected);
        let expansion = "\u{2168}".repeat(64);
        assert_eq!(
            password(expansion.as_bytes()).unwrap().as_str(),
            "IX".repeat(64)
        );
    }

    #[test]
    fn saslprep_keeps_the_unicode_3_2_profile() {
        for (input, expected) in [
            ("\u{2f868}", "\u{2136a}"),
            ("\u{2f874}", "\u{5f33}"),
            ("\u{2f91f}", "\u{43ab}"),
            ("\u{2f95f}", "\u{7aae}"),
            ("\u{2f9bf}", "\u{4d57}"),
            ("\u{f951}", "\u{964b}"),
            ("\u{0627}\u{2132}\u{0628}", "\u{0627}\u{2132}\u{0628}"),
            ("\u{0627}\u{2800}\u{0628}", "\u{0627}\u{2800}\u{0628}"),
        ] {
            assert_eq!(password(input.as_bytes()).unwrap().as_str(), expected);
        }
        for input in ["\u{0627}\u{17b4}\u{0628}", "\u{0627}\u{1885}\u{0628}"] {
            assert!(password(input.as_bytes()).is_none());
        }
    }

    #[test]
    fn invalid_preparation_returns_the_raw_fallback_signal() {
        for input in [
            "",
            "\u{00ad}",
            "\u{0007}",
            "\u{0627}1",
            "a\u{0627}b",
            "\u{0221}",
            "\u{1d2c}",
            "\u{e000}",
        ] {
            assert!(password(input.as_bytes()).is_none());
        }
        assert!(password(&[0xff]).is_none());
        assert_eq!(
            password("\u{0627}\u{0628}".as_bytes()).unwrap().as_str(),
            "\u{0627}\u{0628}"
        );
    }
}
