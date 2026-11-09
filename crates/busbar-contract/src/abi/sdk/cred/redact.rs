// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Redact ingested secret spellings from diagnostic text, including percent/form encoding.

use super::Cred;

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn echo_len(message: &[u8], secret: &[u8], encoded: bool) -> Option<usize> {
    if secret.is_empty() {
        return None;
    }
    let mut i = 0;
    for &byte in secret {
        if encoded
            && message.get(i) == Some(&b'%')
            && message
                .get(i + 1)
                .and_then(|&b| hex(b))
                .zip(message.get(i + 2).and_then(|&b| hex(b)))
                .is_some_and(|(hi, lo)| (hi << 4 | lo) == byte)
        {
            i += 3;
        } else if message.get(i) == Some(&byte) || (byte == b' ' && message.get(i) == Some(&b'+')) {
            i += 1;
        } else {
            return None;
        }
    }
    Some(i)
}

/// Replace complete ingested secret spellings by `<redacted>`, allowing mixed raw and percent
/// encoded bytes, hex case differences, and form-encoded spaces. Owners supply every spelling
/// captured during parsing, including superseded values. This cannot inspect derived values.
pub fn redact_encoded_echoes(text: &str, credentials: &[&Cred]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        let n = credentials
            .iter()
            .flat_map(|credential| {
                [
                    echo_len(&text.as_bytes()[i..], credential.wire(), false),
                    echo_len(&text.as_bytes()[i..], credential.wire(), true),
                ]
            })
            .flatten()
            .filter(|&n| text.is_char_boundary(i + n))
            .max();
        if let Some(n) = n {
            out.push_str("<redacted>");
            i += n;
        } else {
            let c = text[i..].chars().next().expect("within text");
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn mixed_encodings_longest_spellings_and_unicode_are_preserved() {
        let short = Cred::captured(Zeroizing::new(b"a/".to_vec()));
        let long = Cred::captured(Zeroizing::new(b"a/b c".to_vec()));
        let unicode = Cred::captured(Zeroizing::new("é".as_bytes().to_vec()));
        assert_eq!(
            redact_encoded_echoes(
                "a%2Fb+c a/b%20c a%2fb c a/ é %c3%a9 untouched",
                &[&short, &long, &unicode],
            ),
            "<redacted> <redacted> <redacted> <redacted> <redacted> <redacted> untouched"
        );
        let empty = Cred::empty();
        assert_eq!(redact_encoded_echoes("é", &[&empty]), "é");
        let partial = Cred::captured(Zeroizing::new(vec![0xc3]));
        assert_eq!(redact_encoded_echoes("é", &[&partial]), "é");
    }
}
