// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND: `abi/export/`. Every kind op is checked by its `check_<op>`; `scrape` is the
//! one op with a short-buffer path (`needed` above the host's `cap`).

use busbar_contract::abi::export::{
    self, slot, validate, CheckIn, CheckOut, DeliverIn, ScrapeIn, ScrapeOut, ServeIn, ServeOut,
    StatusOut,
};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::KindCode;

use crate::dispatch::{lifecycle_name, Answer, InFrame, Kind, OutFrame};

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
