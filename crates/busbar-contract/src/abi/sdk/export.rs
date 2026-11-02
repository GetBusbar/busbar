// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND'S SHARED SINK PIECES (`abi::export`): what every export sink answered alike,

use std::marker::PhantomData;
use std::mem::size_of;
use std::ptr;

use crate::abi::export::{CheckIn, Route, ScrapeIn, ScrapeOut, ServeIn, ServeOut, StatusOut, Tail};
use crate::abi::mechanism::call::{InHead, Outcome};
use crate::abi::mechanism::door::KindTailHead;
use crate::abi::sdk::lent::Lent;
use crate::abi::sdk::life::{Held, Life, Refusal};
use crate::abi::sdk::out::Out;
use crate::abi::sdk::safe::{Instance, SafeSlot};

/// `scrape`'s refusal on a sink that carries no `metrics` stream.
pub const NO_EXPOSITION: &str = "this sink carries no metrics stream, so it renders no exposition";
/// `serve`'s refusal on a sink that declares no route.
pub const NO_ROUTE: &str = "this sink declares no route, so it serves no request";

/// The export kind's Statement tail: `streams` (as [`ExportStream`](crate::abi::export::ExportStream)

#[must_use]
pub const fn tail(streams: &'static [u8], routes: &'static [Route]) -> Tail {
    Tail {
        head: KindTailHead {
            size: size_of::<Tail>() as u32,
            _reserved: 0,
        },
        streams: if streams.is_empty() {
            ptr::null()
        } else {
            streams.as_ptr()
        },
        streams_len: streams.len(),
        routes: if routes.is_empty() {
            ptr::null()
        } else {
            routes.as_ptr()
        },
        routes_len: routes.len(),
    }
}

/// `scrape` on a sink of `L` that carries no `metrics` stream: REFUSED, [`NO_EXPOSITION`].
#[derive(Debug)]
pub struct NoScrape<L>(PhantomData<L>);

impl<L: Life> SafeSlot for NoScrape<L> {
    type In = ScrapeIn;
    type Out = ScrapeOut;
    type State = Held<L>;
    fn call(
        _: Instance<'_, Held<L>>,
        _: Lent<'_, ScrapeIn>,
        mut out: Out<'_, ScrapeOut>,
    ) -> Outcome {
        out.fail(Refusal::refused(NO_EXPOSITION))
    }
}

/// `serve` on a sink of `L` that declares no route: REFUSED, [`NO_ROUTE`].
#[derive(Debug)]
pub struct NoServe<L>(PhantomData<L>);

impl<L: Life> SafeSlot for NoServe<L> {
    type In = ServeIn;
    type Out = ServeOut;
    type State = Held<L>;
    fn call(_: Instance<'_, Held<L>>, _: Lent<'_, ServeIn>, mut out: Out<'_, ServeOut>) -> Outcome {
        out.fail(Refusal::refused(NO_ROUTE))
    }
}

/// `status` on a sink of `L` with nothing to report: READY.
#[derive(Debug)]
pub struct Quiet<L>(PhantomData<L>);

impl<L: Life> SafeSlot for Quiet<L> {
    type In = InHead;
    type Out = StatusOut;
    type State = Held<L>;
    fn call(_: Instance<'_, Held<L>>, _: Lent<'_, InHead>, _: Out<'_, StatusOut>) -> Outcome {
        Outcome::Ready
    }
}

/// The instance names `check` is handed, in configuration order (an absent name reads empty).
#[must_use]
pub fn instance_names(input: Lent<'_, CheckIn>) -> Vec<String> {
    input
        .instances()
        .iter()
        .map(|c| String::from_utf8_lossy(c.field(|c| &c.name).bytes()).into_owned())
        .collect()
}

/// THE `one_instance` LIMITS CHECK: with more than one instance of the sink configured (`names`,

#[must_use]
pub fn one_instance_reason(names: &[String], why: &str) -> Vec<String> {
    if names.len() > 1 {
        vec![why.to_string()]
    } else {
        Vec::new()
    }
}

/// THE `one_instance` LIMITS CHECK WORDED BY THE SINK (deprecated: the host words the refusal

#[must_use]
pub fn second_instances(names: &[String], alias: &str, why: &str) -> Vec<String> {
    let Some((first, rest)) = names.split_first() else {
        return Vec::new();
    };
    rest.iter()
        .map(|name| {
            format!(
                "export.{name}: a second `module: {alias}` instance (already defined as \
                 '{first}'). {why}"
            )
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/export_tests.rs"]
mod tests;
