// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::export::{
    self, slot, validate, CheckIn, CheckOut, DeliverIn, ScrapeIn, ScrapeOut, ServeIn, ServeOut,
    StatusOut, Tail,
};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::door::{MetricFamily, Statement};
use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::export_stream::ExportStream;

use crate::dispatch::{lifecycle_name, Answer, Context, InFrame, Kind, OutFrame};
// The export kind's Statement read (once per load and bind) lives in `off_path::kinds_export`.
use crate::off_path::kinds_export::facts;
pub(crate) use crate::off_path::kinds_export::{family, owned, route};

/// WHAT AN EXPORT INSTANCE STATES, copied out once at bind: the streams it carries, the routes it
/// serves, and each metric family's name, kind and label keys (what its envelope's metrics are
/// folded under). Read back through [`crate::dispatch::Plugin::context`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportFacts {
    /// The admitted immutable recorder declaration protocol is required after OPEN.
    pub recorder: bool,
    /// The streams, as `ExportStream` bytes.
    pub streams: Vec<u8>,
    /// The routes, in the route vocabulary every kind declares in.
    pub routes: Vec<Route>,
    /// Declared routes requesting the admitted recorder consumer namespace grant.
    pub public_routes: Vec<String>,
    /// Public routes retained by the boot instance across configuration removal.
    pub persistent_routes: Vec<String>,
    /// Each declared metric family: its name, its `FAMILY_*` kind and its label keys.
    pub families: Vec<(String, u8, Vec<String>)>,
    /// The Statement's `one_instance` mark: at most one instance of the plugin may be configured.
    pub one_instance: bool,
    /// Its extensions' `span_records`: it takes each `traces` line's full span record.
    pub span_records: bool,
    /// Its extensions' `whole_batches`: it carries each DELIVER as one unit, so core hands it
    /// everything queued (up to a full batch) instead of a per-slot share.
    pub whole_batches: bool,
}

const EXPORT_TAIL_FROZEN: usize = std::mem::size_of::<Tail>();

// THE PLUGIN MEMORY THE EXPORT KIND'S STATEMENT READ (`off_path::kinds_export`, once per load and
// bind) READS, formed and checked here beside the kind's other unsafe code.

/// A `'static` Statement list of `len` entries at `ptr`, which the caller's check bounded and
/// refused behind NULL.
///
/// # Safety
///
/// `ptr` names `len` live `T`s for the process (Statement data), or `len` is zero.
unsafe fn listed<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// An export Statement's tail lists, its declared families and its extensions, as
/// [`stated_tail`] forms them.
pub(crate) struct StatedTail {
    /// The tail's streams, as `ExportStream` bytes.
    pub(crate) streams: &'static [u8],
    /// The tail's routes.
    pub(crate) routes: &'static [export::Route],
    /// The Statement's metric families.
    pub(crate) families: &'static [MetricFamily],
    /// The Statement's extensions (a NULL blob reads as none).
    pub(crate) ext: &'static [u8],
}

/// The export tail `st` states, judged by `check_tail` and `check_tail_entries`, with its lists,
/// the Statement's families and its extensions formed over the plugin's `'static` data.
pub(crate) fn stated_tail(st: &Statement) -> Result<StatedTail, String> {
    // SAFETY: `Tail` is a `#[repr(C)]` kind tail of integers and pointers (all-zero valid: NULL
    // lists of length 0); a non-NULL kind tail is `'static` plugin data of its stated size.
    let t: Tail =
        unsafe { crate::dispatch::plugin::kind_tail(st, "an export plugin", EXPORT_TAIL_FROZEN) }?;
    let why = |f: Fault| crate::cold::dispatch::kinds::tail_fault("export", f);
    validate::check_tail(&t).map_err(why)?;
    // SAFETY: `check_tail` refused a count behind NULL and bounded both counts; the lists are
    // `'static` plugin data.
    let (streams, routes) = unsafe {
        (
            listed(t.streams, t.streams_len),
            listed(t.routes, t.routes_len),
        )
    };
    // SAFETY: the loaded Statement owns the static route path bytes for this plugin lifetime.
    unsafe { validate::check_tail_entries(streams, routes) }.map_err(why)?;
    // SAFETY: the loader's Statement check bounded `families` and refused it behind NULL.
    let families = unsafe { listed(st.families, st.families_len) };
    // SAFETY: a door's Statement is `'static` plugin data; its extensions blob holds its stated
    // length (a NULL one reads as none).
    let ext = unsafe { crate::dispatch::plugin::blob_bytes(st.extensions) };
    Ok(StatedTail {
        streams,
        routes,
        families,
        ext,
    })
}

/// One declared metric family's label keys.
pub(crate) fn label_keys(f: &MetricFamily) -> &'static [AbiStr] {
    // SAFETY: the loader's Statement check bounded each family's label keys and refused them
    // behind NULL; they are `'static` plugin data.
    unsafe { listed(f.label_keys, f.label_keys_len) }
}

/// The export kind.
#[derive(Debug, Clone, Copy)]
pub struct Export;

// SAFETY: `#[repr(C)]` in `abi/export/`, each leading with its head; host buffers only.
unsafe impl InFrame for DeliverIn {}
unsafe impl InFrame for ScrapeIn {}
unsafe impl InFrame for CheckIn {}
unsafe impl InFrame for ServeIn {}
unsafe impl OutFrame for ScrapeOut {}
unsafe impl OutFrame for StatusOut {}
unsafe impl OutFrame for CheckOut {}
unsafe impl OutFrame for ServeOut {}

impl crate::dispatch::kind_seal::Validated for Export {}

impl Kind for Export {
    const CODE: KindCode = KindCode::Export;
    type Ops = export::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn context(st: &Statement) -> Result<Option<Box<Context>>, String> {
        Ok(Some(Box::new(facts(st)?)))
    }

    fn optional_by_statement(s: u32, st: &Statement) -> bool {
        let Ok(f) = facts(st) else {
            return false;
        };
        let metrics = ExportStream::Metrics as u8;
        match s {
            slot::DELIVER => f.streams.iter().all(|&b| b == metrics),
            slot::SCRAPE => !f.streams.contains(&metrics),
            slot::SERVE => f.routes.is_empty(),
            _ => false,
        }
    }

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::DELIVER => "deliver",
            slot::SCRAPE => "scrape",
            slot::STATUS => "status",
            slot::CHECK => "check",
            slot::SERVE => "serve",
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::DELIVER => validate::check_deliver(a.out::<OutHead>()?),
            slot::SCRAPE => {
                validate::check_scrape(a.out::<ScrapeOut>()?, a.input::<ScrapeIn>()?.cap)
            }
            slot::STATUS => {
                a.input::<InHead>()?;
                validate::check_status(a.out::<StatusOut>()?)
            }
            slot::CHECK => validate::check_check(a.out::<CheckOut>()?),
            slot::SERVE => validate::check_serve(a.out::<ServeOut>()?),
            _ => Ok(()),
        }
    }

    fn short(a: &Answer) -> bool {
        a.slot == slot::SCRAPE
            && a.outcome == Outcome::Failed
            && a.out::<ScrapeOut>().is_ok_and(|o| o.needed != 0)
    }
}

#[cfg(test)]
mod owned_tests {
    use super::*;

    #[test]
    fn a_route_path_that_is_not_utf8_is_refused_not_repaired() {
        let bad: &'static [u8] = b"/\xff";
        let r = export::Route {
            path: AbiStr {
                ptr: bad.as_ptr(),
                len: bad.len(),
            },
            method: AbiStr {
                ptr: b"GET".as_ptr(),
                len: 3,
            },
            auth: export::ROUTE_AUTH_NONE,
            _reserved: 0,
        };
        assert!(route(&r).is_err(), "a lossy U+FFFD path must not load");
    }
}
