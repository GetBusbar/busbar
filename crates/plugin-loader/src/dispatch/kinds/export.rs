// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND: `abi/export/`. Every kind op is checked by its `check_<op>`; `scrape` is the
//! one op with a short-buffer path (`needed` above the host's `cap`). The Statement tail is read
//! once at bind, through the kind's own `check_tail` / `check_tail_entries`, into [`ExportFacts`].

use busbar_contract::abi::export::{
    self, slot, validate, CheckIn, CheckOut, DeliverIn, ScrapeIn, ScrapeOut, ServeIn, ServeOut,
    StatusOut, Tail,
};
use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::abi::mechanism::KindCode;

use crate::dispatch::{lifecycle_name, Answer, Context, InFrame, Kind, OutFrame};

/// WHAT AN EXPORT INSTANCE STATES, copied out once at bind: the streams it carries, the routes it
/// serves, and each metric family's name, kind and label keys (what its envelope's metrics are
/// folded under). Read back through [`crate::dispatch::Plugin::context`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportFacts {
    /// The streams, as `ExportStream` bytes.
    pub streams: Vec<u8>,
    /// The routes, in the route vocabulary every kind declares in.
    pub routes: Vec<Route>,
    /// Each declared metric family: its name, its `FAMILY_*` kind and its label keys.
    pub families: Vec<(String, u8, Vec<String>)>,
}

/// A `'static` Statement string, copied; `None` when malformed.
fn owned(s: AbiStr) -> Option<String> {
    crate::dispatch::plugin::str_bytes(s).map(|b| String::from_utf8_lossy(b).into_owned())
}

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

/// One declared route, in the route vocabulary: its path, a method the vocabulary names and its
/// `ROUTE_AUTH_*` bar (the tail's entry check bounded the code).
fn route(r: &export::Route) -> Result<Route, String> {
    let path = owned(r.path).ok_or("an export route's path is over-long")?;
    let method = owned(r.method).ok_or("an export route's method is over-long")?;
    let methods = [
        RouteMethod::Get,
        RouteMethod::Post,
        RouteMethod::Put,
        RouteMethod::Patch,
        RouteMethod::Delete,
    ];
    let method = methods
        .into_iter()
        .find(|m| m.as_str() == method)
        .ok_or_else(|| format!("the export route {path} names the method `{method}`"))?;
    let auth = match r.auth {
        export::ROUTE_AUTH_NONE => RouteAuth::None,
        export::ROUTE_AUTH_KEY => RouteAuth::Key,
        _ => RouteAuth::Admin,
    };
    Ok(Route { path, method, auth })
}

/// Read and judge the export tail ([`validate::check_tail`], then [`validate::check_tail_entries`]).
fn facts(st: &Statement) -> Result<ExportFacts, String> {
    let p = st.kind_tail;
    if p.is_null() {
        return Err("an export plugin states no kind tail".into());
    }
    // SAFETY: a non-NULL kind tail is `'static` plugin data leading with a `KindTailHead`; the
    // whole tail is read only once its size covers this host's `Tail`.
    let size = unsafe { (*p).size };
    if (size as usize) < std::mem::size_of::<Tail>() {
        return Err(format!(
            "the export tail is {size} bytes, smaller than this host's"
        ));
    }
    // SAFETY: as above.
    let t = unsafe { p.cast::<Tail>().read_unaligned() };
    let why = |f: Fault| format!("the export tail breaks {:?} at {}", f.rule, f.field);
    validate::check_tail(&t).map_err(why)?;
    // SAFETY: `check_tail` refused a count behind NULL and bounded both counts; the lists are
    // `'static` plugin data.
    let (streams, routes) = unsafe {
        (
            listed(t.streams, t.streams_len),
            listed(t.routes, t.routes_len),
        )
    };
    validate::check_tail_entries(streams, routes).map_err(why)?;
    let routes = routes.iter().map(route).collect::<Result<Vec<_>, _>>()?;
    // SAFETY: the loader's Statement check bounded `families` and refused it behind NULL.
    let declared = unsafe { listed(st.families, st.families_len) };
    let mut families = Vec::with_capacity(declared.len());
    for f in declared {
        // SAFETY: as above, for each family's label keys.
        let keys = unsafe { listed(f.label_keys, f.label_keys_len) };
        let keys = keys
            .iter()
            .map(|k| owned(*k))
            .collect::<Option<Vec<_>>>()
            .ok_or("a metric family's label key is over-long")?;
        let name = owned(f.name).ok_or("a metric family's name is over-long")?;
        families.push((name, f.kind, keys));
    }
    Ok(ExportFacts {
        streams: streams.to_vec(),
        routes,
        families,
    })
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

impl Kind for Export {
    const CODE: KindCode = KindCode::Export;
    type Ops = export::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn context(st: &Statement) -> Result<Option<Box<Context>>, String> {
        Ok(Some(Box::new(facts(st)?)))
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
