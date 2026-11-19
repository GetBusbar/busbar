// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seven typed faces over the one crossing place: one function per method of each kind, holding
//! that method's table index, its head record and its text and blob positions, exactly as the contract's
//! method table states them (`LAYOUT.tsv`: kind, slot, method, role, head, texts, blobs). Nothing here
//! builds a call or invokes an entry: each function fills a `Frame` and hands it to one of `call`'s five.
//!
//! A head record is `#[repr(C)]`, little-endian on every supported target, each number at its natural
//! alignment from the start of the head; where the table's alignment leaves a gap the record names it
//! (`_gap`, always zero) so the record has no hidden padding and its bytes can be lent as they stand.

pub mod auth;
pub mod export;
pub mod hook;
pub mod plane;
pub mod secret;
pub mod store;
pub mod transport;

/// The shared body of every kind's `Proxy`: the bound instance, `bind` and `instance`.
macro_rules! proxy {
    ($Marker:ident) => {
        /// This kind's typed face over one live instance.
        #[derive(Clone)]
        pub struct Proxy {
            to: $crate::call::Bound<busbar_ffi::kind::$Marker>,
        }

        impl Proxy {
            /// None when `inst` is an instance of another kind.
            pub fn bind(
                inst: std::sync::Arc<busbar_plugin_abi::host_side::driver::Instance>,
            ) -> Option<Self> {
                Some(Proxy {
                    to: $crate::call::Bound::bind(inst)?,
                })
            }

            pub fn instance(
                &self,
            ) -> &std::sync::Arc<busbar_plugin_abi::host_side::driver::Instance> {
                self.to.instance()
            }
        }
    };
}
pub(crate) use proxy;

/// The future of one async method.
pub trait Chained<'a>:
    core::future::Future<
        Output = Result<
            busbar_plugin_abi::host_side::answer::OwnedAnswer,
            busbar_plugin_abi::fail::CallError,
        >,
    > + Send
    + 'a
{
}
impl<'a, F> Chained<'a> for F where
    F: core::future::Future<
            Output = Result<
                busbar_plugin_abi::host_side::answer::OwnedAnswer,
                busbar_plugin_abi::fail::CallError,
            >,
        > + Send
        + 'a
{
}
