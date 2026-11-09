// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bounded, inert login presentation declared by an auth instance. No markup or URLs.

/// OPEN/REFRESH extension carrying one JSON [`LoginPresentation`]. Absence is generic.
pub const EXT_LOGIN_PRESENTATION: &str = "auth.login_presentation";
/// Maximum encoded presentation bytes, checked before JSON allocation.
pub const MAX_PRESENTATION_BYTES: usize = 16 * 1024;

/// A provider-owned label and optional inert vector icon.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginPresentation {
    /// Nonempty UTF-8 text, at most 80 bytes, with no control characters.
    pub label: String,
    /// Optional icon. The host supplies every markup element and attribute name.
    pub icon: Option<LoginIcon>,
}

/// A bounded filled-path icon; no scripts, styles, links, image references or markup.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginIcon {
    /// Width and height of a view box starting at (0, 0), each in 1..=1024.
    pub view_box: [u16; 2],
    /// One to sixteen filled paths, at most 8192 path-data bytes combined.
    pub paths: Vec<LoginIconPath>,
}

/// One path using SVG's numeric path vocabulary, with a restricted solid fill.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginIconPath {
    /// At most 4096 ASCII bytes. Coordinates must be finite and within ±1,000,000.
    pub data: String,
    /// `currentColor` or one six-digit `#RRGGBB` color; never a CSS function or URL.
    pub fill: String,
}

impl LoginPresentation {
    /// Check resource bounds and inert rendering grammar. Error text never contains input bytes.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.label.is_empty()
            || self.label.len() > 80
            || self.label.chars().any(char::is_control)
        {
            return Err("invalid auth login presentation label (1..=80 UTF-8 bytes required)");
        }
        if let Some(icon) = &self.icon {
            if icon.view_box.iter().any(|n| !(1..=1024).contains(n))
                || icon.paths.is_empty()
                || icon.paths.len() > 16
                || icon.paths.iter().map(|p| p.data.len()).sum::<usize>() > 8192
            {
                return Err("invalid auth login presentation icon bounds");
            }
            for path in &icon.paths {
                let fill = path.fill.as_bytes();
                if path.fill != "currentColor"
                    && !(fill.len() == 7
                        && fill[0] == b'#'
                        && fill[1..].iter().all(u8::is_ascii_hexdigit))
                {
                    return Err("invalid auth login presentation fill");
                }
                if path.data.len() > 4096 || !valid_path(&path.data) {
                    return Err("invalid auth login presentation numeric path");
                }
            }
        }
        Ok(())
    }
}

/// Decode exactly one optional presentation, refusing duplicate, truncated or malformed data.
/// The supplied bytes are the already-lent lifecycle extension envelope.
pub fn login_presentation(extensions: &[u8]) -> Result<Option<LoginPresentation>, &'static str> {
    let mut out = None;
    let mut consumed = 0usize;
    for (key, value) in crate::abi::mechanism::extensions::entries(extensions) {
        consumed += 2 + key.len() + 4 + value.len();
        if key != EXT_LOGIN_PRESENTATION.as_bytes() {
            continue;
        }
        if out.is_some() || value.len() > MAX_PRESENTATION_BYTES {
            return Err("duplicate or oversized auth login presentation");
        }
        let presentation: LoginPresentation =
            serde_json::from_slice(value).map_err(|_| "malformed auth login presentation JSON")?;
        presentation.validate()?;
        out = Some(presentation);
    }
    if consumed != extensions.len() {
        return Err("truncated auth instance metadata");
    }
    Ok(out)
}

fn valid_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let (mut at, mut command, mut arity, mut count) = (0, 0u8, 0, 0usize);
    while at < bytes.len() {
        if bytes[at].is_ascii_whitespace() || bytes[at] == b',' {
            at += 1;
            continue;
        }
        if bytes[at].is_ascii_alphabetic() {
            if command != 0 && arity != 0 && (count == 0 || count % arity != 0) {
                return false;
            }
            let next = bytes[at].to_ascii_uppercase();
            if command == 0 && next != b'M' {
                return false;
            }
            arity = match next {
                b'M' | b'L' | b'T' => 2,
                b'H' | b'V' => 1,
                b'C' => 6,
                b'S' | b'Q' => 4,
                b'A' => 7,
                b'Z' => 0,
                _ => return false,
            };
            command = next;
            count = 0;
            at += 1;
            continue;
        }
        if command == 0 || arity == 0 {
            return false;
        }
        if command == b'A' && matches!(count % 7, 3 | 4) {
            if !matches!(bytes[at], b'0' | b'1') {
                return false;
            }
            at += 1;
            count += 1;
            continue;
        }
        let start = at;
        if matches!(bytes.get(at), Some(b'+' | b'-')) {
            at += 1;
        }
        let integer = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        let mut digits = at - integer;
        if bytes.get(at) == Some(&b'.') {
            at += 1;
            let fractional = at;
            while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                at += 1;
            }
            digits += at - fractional;
        }
        if digits == 0 {
            return false;
        }
        if matches!(bytes.get(at), Some(b'e' | b'E')) {
            at += 1;
            if matches!(bytes.get(at), Some(b'+' | b'-')) {
                at += 1;
            }
            let exponent = at;
            while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                at += 1;
            }
            if at == exponent {
                return false;
            }
        }
        let Ok(number) = path[start..at].parse::<f64>() else {
            return false;
        };
        if !number.is_finite() || number.abs() > 1_000_000.0 {
            return false;
        }
        if command == b'A' {
            if count % 7 < 2 && number < 0.0 {
                return false;
            }
            if matches!(count % 7, 3 | 4) && number != 0.0 && number != 1.0 {
                return false;
            }
        }
        count += 1;
    }
    command != 0 && (arity == 0 || (count > 0 && count % arity == 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn declaration(data: &str) -> LoginPresentation {
        LoginPresentation {
            label: "Example".into(),
            icon: Some(LoginIcon {
                view_box: [16, 16],
                paths: vec![LoginIconPath {
                    data: data.into(),
                    fill: "currentColor".into(),
                }],
            }),
        }
    }
    #[test]
    fn presentation_accepts_only_bounded_inert_data() {
        for path in [
            "M0 0h9v9H0z",
            "M1 2C3.5-4.5 5 6 7 8z",
            "M0 0A8.01 8.01 0 0016 8z",
        ] {
            assert!(declaration(path).validate().is_ok(), "{path}");
        }
        for path in [
            "",
            "L1 2",
            "M1",
            "M0 0X1 2",
            "M0 0LNaN 1",
            "M0 0L1e999 1",
            "M0 0L1000001 0",
            "M0 0\" onclick=\"alert(1)",
            "M0 0A2 2 0 2 0 1 1",
        ] {
            assert!(declaration(path).validate().is_err(), "{path}");
        }
        let mut p = declaration("M0 0L1 1");
        p.label = "é".repeat(41);
        assert!(p.validate().is_err());
        p.label = "Safe".into();
        p.icon.as_mut().unwrap().paths[0].fill = "url(https://example.test/icon)".into();
        assert!(p.validate().is_err());
    }
    #[test]
    fn presentation_envelope_is_strict_and_absence_is_generic() {
        use crate::abi::mechanism::extensions::encode;
        assert_eq!(login_presentation(&[]), Ok(None));
        for bad in [
            b"null".as_slice(),
            br#"{"label":"ok","icon":null,"html":"<script>"}"#,
            b"\xff",
        ] {
            assert!(login_presentation(&encode(&[(EXT_LOGIN_PRESENTATION, bad)])).is_err());
        }
        assert!(login_presentation(&encode(&[(
            EXT_LOGIN_PRESENTATION,
            &vec![b' '; MAX_PRESENTATION_BYTES + 1]
        )]))
        .is_err());
        let json = serde_json::to_vec(&declaration("M0 0L1 1")).unwrap();
        assert!(login_presentation(&encode(&[
            (EXT_LOGIN_PRESENTATION, &json),
            (EXT_LOGIN_PRESENTATION, &json)
        ]))
        .is_err());
        let mut truncated = encode(&[(EXT_LOGIN_PRESENTATION, &json)]);
        truncated.pop();
        assert!(login_presentation(&truncated).is_err());
    }
}
