// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The depth guard and the string skip answer exactly as the byte-at-a-time scans they replaced,
//! over every short input built from the bytes that steer them.

use busbar_json::{exceeds_max_depth, past_string_body};

/// The byte-at-a-time depth guard the string skip replaced.
fn depth_by_bytes(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// The byte-at-a-time string skip the span scanner used.
fn string_by_bytes(bytes: &[u8], body: usize) -> Option<usize> {
    let mut i = body;
    while let Some(c) = bytes.get(i) {
        match c {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

const ALPHABET: [u8; 7] = [b'"', b'\\', b'{', b'}', b'[', b']', b'a'];

/// Both scans agree on `bytes`: the depth guard at small limits, the string skip from every
/// `step`-th position (and one past the end).
fn check(bytes: &[u8], step: usize) {
    for max in 0..4 {
        assert_eq!(
            exceeds_max_depth(bytes, max),
            depth_by_bytes(bytes, max),
            "depth guard, max {max}, input {:?}",
            String::from_utf8_lossy(bytes)
        );
    }
    for body in (0..=bytes.len() + 1).step_by(step) {
        assert_eq!(
            past_string_body(bytes, body),
            string_by_bytes(bytes, body),
            "string skip from {body}, input {:?}",
            String::from_utf8_lossy(bytes)
        );
    }
}

#[test]
fn every_input_up_to_seven_bytes_answers_as_the_byte_scan() {
    // Each input alone, and behind 19 plain bytes: a string skip that starts in them passes its
    // byte-by-byte prefix and searches the input.
    const PLAIN: usize = 19;
    let mut input = Vec::new();
    for len in 0..=7u32 {
        for mut n in 0..ALPHABET.len().pow(len) {
            input.clear();
            input.resize(PLAIN, b'a');
            for _ in 0..len {
                input.push(ALPHABET[n % ALPHABET.len()]);
                n /= ALPHABET.len();
            }
            check(&input[PLAIN..], 1);
            check(&input, 1);
        }
    }
}

#[test]
fn long_strings_with_escapes_answer_as_the_byte_scan() {
    let mut text = br#"{"messages":[{"role":"user","content":""#.to_vec();
    for i in 0..5000u32 {
        text.extend_from_slice(match i % 7 {
            0 => br#"\""#.as_slice(),
            1 => br"\\",
            2 => b"{[",
            _ => b"plain text ",
        });
    }
    text.extend_from_slice(br#""}]}"#);
    check(&text, 97);
    // The same document cut inside its string: the guard sees an unterminated string.
    let open = text.len() - 4;
    check(&text[..open], 97);
}
