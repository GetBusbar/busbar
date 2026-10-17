// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SNAPSHOT LAYOUT (`abi::host::service`, `snapshot.read`): the host's metric families laid out
//! in the CALLER's buffer, in the export kind's scrape layout — the [`ScrapeFamily`] array at offset
//! `0`, then every family's [`ScrapeSample`]s, then every sample's [`ScrapeLabel`]s, then the bytes
//! of every string, each pointer naming a range of that same buffer. The caller reads it as it reads
//! a `scrape` op's lent families (`abi::sdk::services::Services::snapshot_read`).

use std::mem::size_of;

use busbar_contract::abi::export::{ScrapeFamily, ScrapeLabel, ScrapeSample};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::export_calls::Family;

/// The counts a layout of `families` holds: samples, labels and string bytes.
fn counts(families: &[Family]) -> (usize, usize, usize) {
    let opt = |s: &Option<String>| s.as_ref().map_or(0, String::len);
    families.iter().fold((0, 0, 0), |(s, l, b), f| {
        let (fs, fl, fb) = f.samples.iter().fold((0, 0, 0), |(s, l, b), x| {
            let labels: usize = x.labels.iter().map(|(k, v)| k.len() + v.len()).sum();
            (
                s + 1,
                l + x.labels.len(),
                b + x.name.len() + x.value.len() + labels,
            )
        });
        (
            s + fs,
            l + fl,
            b + fb + f.name.len() + opt(&f.help) + opt(&f.unit),
        )
    })
}

/// The bytes the layout of `families` takes.
#[must_use]
pub fn size_of_layout(families: &[Family]) -> usize {
    let (samples, labels, bytes) = counts(families);
    families.len() * size_of::<ScrapeFamily>()
        + samples * size_of::<ScrapeSample>()
        + labels * size_of::<ScrapeLabel>()
        + bytes
}

/// A bump writer over the caller's buffer.
struct Bump {
    base: *mut u8,
    at: usize,
}

impl Bump {
    /// Copy `s` in; its range as a string of the buffer.
    ///
    /// # Safety
    /// `s.len()` bytes from `at` lie inside the caller's buffer.
    unsafe fn text(&mut self, s: &str) -> AbiStr {
        // SAFETY: the caller's contract.
        let p = unsafe { self.base.add(self.at) };
        if !s.is_empty() {
            // SAFETY: as above; the source is ours and does not overlap the caller's buffer.
            unsafe { std::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len()) };
        }
        self.at += s.len();
        AbiStr {
            ptr: p.cast_const(),
            len: s.len(),
        }
    }

    /// [`Self::text`] for an optional string: `None` is absent (NULL).
    ///
    /// # Safety
    /// As [`Self::text`].
    unsafe fn opt(&mut self, s: Option<&str>) -> AbiStr {
        match s {
            // SAFETY: the caller's contract.
            Some(s) => unsafe { self.text(s) },
            None => AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
        }
    }
}

/// Lay `families` out at `buf`; the bytes used ([`size_of_layout`]).
///
/// # Safety
/// `buf` is the caller's writable buffer of at least [`size_of_layout`] bytes, aligned for
/// [`ScrapeFamily`] (`SNAPSHOT_ALIGN`).
#[must_use]
pub unsafe fn lay_out(families: &[Family], buf: *mut u8) -> usize {
    let (samples, labels, _) = counts(families);
    let samples_at = families.len() * size_of::<ScrapeFamily>();
    let labels_at = samples_at + samples * size_of::<ScrapeSample>();
    let mut bytes = Bump {
        base: buf,
        at: labels_at + labels * size_of::<ScrapeLabel>(),
    };
    let (mut s_at, mut l_at) = (samples_at, labels_at);
    for (fi, f) in families.iter().enumerate() {
        // SAFETY (every write below): each record lies inside the layout's own region of the
        // caller's buffer, which holds the whole layout and the scrape layout's alignment; every
        // record size is a multiple of that alignment, so each region starts aligned.
        let first_sample = unsafe { buf.add(s_at) }.cast::<ScrapeSample>();
        for x in &f.samples {
            let first_label = unsafe { buf.add(l_at) }.cast::<ScrapeLabel>();
            for (k, v) in &x.labels {
                let label = ScrapeLabel {
                    key: unsafe { bytes.text(k) },
                    value: unsafe { bytes.text(v) },
                };
                unsafe { buf.add(l_at).cast::<ScrapeLabel>().write(label) };
                l_at += size_of::<ScrapeLabel>();
            }
            let sample = ScrapeSample {
                name: unsafe { bytes.text(&x.name) },
                labels: if x.labels.is_empty() {
                    std::ptr::null()
                } else {
                    first_label.cast_const()
                },
                labels_len: x.labels.len(),
                value: unsafe { bytes.text(&x.value) },
            };
            unsafe { buf.add(s_at).cast::<ScrapeSample>().write(sample) };
            s_at += size_of::<ScrapeSample>();
        }
        let family = ScrapeFamily {
            name: unsafe { bytes.text(&f.name) },
            help: unsafe { bytes.opt(f.help.as_deref()) },
            unit: unsafe { bytes.opt(f.unit.as_deref()) },
            kind: f.kind,
            _reserved: [0; 7],
            samples: if f.samples.is_empty() {
                std::ptr::null()
            } else {
                first_sample.cast_const()
            },
            samples_len: f.samples.len(),
        };
        unsafe {
            buf.add(fi * size_of::<ScrapeFamily>())
                .cast::<ScrapeFamily>()
                .write(family);
        }
    }
    bytes.at
}

#[cfg(test)]
#[path = "tests/snapshot_tests.rs"]
mod tests;
