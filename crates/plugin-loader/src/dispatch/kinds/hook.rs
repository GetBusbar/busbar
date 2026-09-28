// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND: `abi/hook/`. Every kind op is checked by its `check_<op>`. `decide` and
//! `transform` write into host buffers [`DecideIn`] names, so their checks take the caps from that
//! `in`, and they are the two ops with a short-buffer path (a `*_needed` above its cap);
//! `configure` is checked against the version [`ConfigureIn`] pushed. No hook check reads a slice
//! a plugin-reported count names, so none is built here.

use busbar_contract::abi::hook::{
    self, slot, validate, ConfigureIn, ConfigureOut, DecideIn, DecideOut, DescribeOut, NotifyIn,
    ServeIn, ServeOut, StatusOut, TransformOut,
};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::KindCode;

use crate::dispatch::{lifecycle_name, Answer, InFrame, Kind, OutFrame};

/// The hook kind.
#[derive(Debug, Clone, Copy)]
pub struct Hook;

// SAFETY: `#[repr(C)]` in `abi/hook/`, each leading with its head; host buffers only.
unsafe impl InFrame for DecideIn {}
unsafe impl InFrame for NotifyIn {}
unsafe impl InFrame for ConfigureIn {}
unsafe impl InFrame for ServeIn {}
unsafe impl OutFrame for DecideOut {}
unsafe impl OutFrame for TransformOut {}
unsafe impl OutFrame for ConfigureOut {}
unsafe impl OutFrame for StatusOut {}
unsafe impl OutFrame for DescribeOut {}
unsafe impl OutFrame for ServeOut {}

impl Kind for Hook {
    const CODE: KindCode = KindCode::Hook;
    type Ops = hook::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::DECIDE => "decide",
            slot::TRANSFORM => "transform",
            slot::NOTIFY => "notify",
            slot::CONFIGURE => "configure",
            slot::STATUS => "status",
            slot::DESCRIBE => "describe",
            slot::SERVE => "serve",
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::DECIDE => {
                let i = a.input::<DecideIn>()?;
                validate::check_decide(
                    a.out::<DecideOut>()?,
                    i.reject_message_cap,
                    i.restrict_tags_cap,
                    i.order_cap,
                )
            }
            slot::TRANSFORM => {
                let i = a.input::<DecideIn>()?;
                validate::check_transform(
                    a.out::<TransformOut>()?,
                    i.reject_message_cap,
                    i.rewrite_cap,
                )
            }
            slot::NOTIFY => {
                a.input::<NotifyIn>()?;
                validate::check_notify(a.out::<OutHead>()?)
            }
            slot::CONFIGURE => validate::check_configure(
                a.out::<ConfigureOut>()?,
                a.input::<ConfigureIn>()?.version,
            ),
            slot::STATUS => {
                a.input::<InHead>()?;
                validate::check_status(a.out::<StatusOut>()?)
            }
            slot::DESCRIBE => {
                a.input::<InHead>()?;
                validate::check_describe(a.out::<DescribeOut>()?)
            }
            slot::SERVE => {
                a.input::<ServeIn>()?;
                validate::check_serve(a.out::<ServeOut>()?)
            }
            _ => Ok(()),
        }
    }

    fn short(a: &Answer) -> bool {
        if a.outcome != Outcome::Failed {
            return false;
        }
        match a.slot {
            slot::DECIDE => a.out::<DecideOut>().is_ok_and(|o| {
                o.reject_message_needed != 0 || o.restrict_tags_needed != 0 || o.order_needed != 0
            }),
            slot::TRANSFORM => a
                .out::<TransformOut>()
                .is_ok_and(|o| o.reject_message_needed != 0 || o.rewrite_needed != 0),
            _ => false,
        }
    }
}
