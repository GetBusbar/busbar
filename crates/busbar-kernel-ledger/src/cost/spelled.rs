// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Short text spelled on the stack: a figure written with `write!` into a fixed buffer and borrowed
//! back, so a parser or a serializer is handed its text without a heap allocation.

/// Up to `N` bytes of text written with `write!`. A piece that would run past `N` bytes is refused
/// whole (the write fails), so what is held is always the complete pieces that fit.
pub(crate) struct Spelled<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Spelled<N> {
    /// Nothing spelled yet.
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    /// The text spelled so far.
    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or_default()
    }
}

impl<const N: usize> std::fmt::Write for Spelled<N> {
    fn write_str(&mut self, piece: &str) -> std::fmt::Result {
        let end = self
            .len
            .checked_add(piece.len())
            .filter(|&end| end <= N)
            .ok_or(std::fmt::Error)?;
        self.buf[self.len..end].copy_from_slice(piece.as_bytes());
        self.len = end;
        Ok(())
    }
}
