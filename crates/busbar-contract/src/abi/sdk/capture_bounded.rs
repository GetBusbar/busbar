// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bound diagnostic formatting before a formatter expands its entire value.

use std::fmt;

pub(super) struct Bounded {
    text: String,
    limit: usize,
    truncated: bool,
}

impl Bounded {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            text: String::new(),
            limit,
            truncated: false,
        }
    }

    pub(super) fn is_full(&self) -> bool {
        self.truncated || self.text.len() == self.limit
    }

    pub(super) fn as_str(&self) -> &str {
        &self.text
    }

    pub(super) fn into_string(self) -> String {
        self.text
    }
}

impl fmt::Write for Bounded {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.truncated {
            return Err(fmt::Error);
        }
        let room = self.limit - self.text.len();
        if text.len() <= room {
            self.text.push_str(text);
            return Ok(());
        }
        let mut end = room;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.text.push_str(&text[..end]);
        self.truncated = true;
        Err(fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fmt::Write as _;

    #[test]
    fn formatting_stops_at_the_bound_instead_of_expanding_the_value() {
        struct Expensive<'a>(&'a Cell<usize>);
        impl fmt::Debug for Expensive<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for _ in 0..16 * 1024 * 1024 {
                    self.0.set(self.0.get() + 1);
                    f.write_str("x")?;
                }
                Ok(())
            }
        }
        let calls = Cell::new(0);
        let mut out = Bounded::new(4096);
        assert!(write!(out, "{:?}", Expensive(&calls)).is_err());
        assert_eq!(calls.get(), 4097);
        assert_eq!(out.as_str(), "x".repeat(4096));
        assert!(out.is_full());
        assert_eq!(out.into_string().len(), 4096);
    }

    #[test]
    fn truncation_keeps_a_utf8_prefix_and_never_appends_after_a_cut() {
        let mut out = Bounded::new(5);
        assert!(out.write_str("aé🦀z").is_err());
        assert_eq!(out.as_str(), "aé");
        assert!(out.is_full());
        assert!(out.write_str("!").is_err());
        assert_eq!(out.into_string(), "aé");
    }

    #[test]
    fn exact_fit_empty_values_and_zero_limit_are_well_defined() {
        let mut out = Bounded::new(3);
        assert!(out.write_str("aé").is_ok());
        assert!(out.is_full());
        assert!(out.write_str("").is_ok());
        assert!(out.write_str("!").is_err());
        assert_eq!(out.into_string(), "aé");
        let mut zero = Bounded::new(0);
        assert!(zero.is_full());
        assert!(zero.write_str("").is_ok());
        assert!(zero.write_str("x").is_err());
        assert_eq!(zero.into_string(), "");
    }

    #[test]
    fn event_parts_keep_the_original_prefix_and_field_order() {
        let mut out = Bounded::new(18);
        assert!(write!(out, "{}: {}{}", "target", "message", " answer=42").is_err());
        assert_eq!(out.into_string(), "target: message an");
    }
}
