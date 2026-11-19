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

/// The head records against the contract's method table (`LAYOUT.tsv`, column `head`): each number at
/// its natural alignment from the start of the head, in the table's order. A record that drifts from
/// the table is a call the plugin's generated reader faults on, so the drift is caught here, with no
/// plugin and no build of anything else.
#[cfg(test)]
mod layout_tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn auth_heads() {
        // verify: flags:u32,_r:u32,now_s:u64
        assert_eq!(size_of::<auth::VerifyHead>(), 16);
        assert_eq!(offset_of!(auth::VerifyHead, flags), 0);
        assert_eq!(offset_of!(auth::VerifyHead, now_s), 8);
        // login: step:u32
        assert_eq!(size_of::<auth::LoginHead>(), 4);
    }

    #[test]
    fn hook_heads() {
        // on, on_io: point:u32
        assert_eq!(size_of::<hook::PointHead>(), 4);
    }

    #[test]
    fn export_heads() {
        // deliver: stream:u32,delivery:u64,attempt:u32,lines:u32
        assert_eq!(size_of::<export::DeliverHead>(), 24);
        assert_eq!(offset_of!(export::DeliverHead, stream), 0);
        assert_eq!(offset_of!(export::DeliverHead, delivery), 8);
        assert_eq!(offset_of!(export::DeliverHead, attempt), 16);
        assert_eq!(offset_of!(export::DeliverHead, lines), 20);
        // render: scope:u32; confirm: delivery:u64
        assert_eq!(size_of::<export::ScopeHead>(), 4);
        assert_eq!(size_of::<export::ConfirmHead>(), 8);
    }

    #[test]
    fn plane_heads() {
        // request: route:u32,flags:u32,auth:u32,_r:u32,request_id:u64,carrier:u64
        assert_eq!(size_of::<plane::RequestHead>(), 32);
        assert_eq!(offset_of!(plane::RequestHead, auth), 8);
        assert_eq!(offset_of!(plane::RequestHead, request_id), 16);
        assert_eq!(offset_of!(plane::RequestHead, carrier), 24);
        // render: the request head, then what:u32 (36 bytes sent)
        assert_eq!(offset_of!(plane::RenderHead, what), 32);
        assert_eq!(plane::RENDER_HEAD_LEN, 36);
        assert!(plane::RENDER_HEAD_LEN <= size_of::<plane::RenderHead>());
        // select_resources: mode:u32,route:u32,flags:u32,auth:u32,_r:u32,request_id:u64,carrier:u64
        assert_eq!(size_of::<plane::SelectHead>(), 40);
        assert_eq!(offset_of!(plane::SelectHead, mode), 0);
        assert_eq!(offset_of!(plane::SelectHead, route), 4);
        assert_eq!(offset_of!(plane::SelectHead, auth), 12);
        assert_eq!(offset_of!(plane::SelectHead, request_id), 24);
        assert_eq!(offset_of!(plane::SelectHead, carrier), 32);
        // upstream, probe, channel: attempt:u32,flags:u32
        assert_eq!(size_of::<plane::TargetHead>(), 8);
        // piece: from:u32,exchange:u32,flags:u32
        assert_eq!(size_of::<plane::PieceHead>(), 12);
        assert_eq!(offset_of!(plane::PieceHead, flags), 8);
        // admin: op:u32
        assert_eq!(size_of::<plane::AdminHead>(), 4);
    }

    #[test]
    fn transport_heads() {
        // begin: role:u32,flags:u32,mono_ns:u64
        assert_eq!(size_of::<transport::BeginHead>(), 16);
        assert_eq!(offset_of!(transport::BeginHead, mono_ns), 8);
        // emit: stream:u64,pieces:u32,arg:u32,credit:u64
        assert_eq!(size_of::<transport::EmitHead>(), 24);
        assert_eq!(offset_of!(transport::EmitHead, pieces), 8);
        assert_eq!(offset_of!(transport::EmitHead, arg), 12);
        assert_eq!(offset_of!(transport::EmitHead, credit), 16);
        // datagram: path:u32,flags:u32; event: ev:u32; offer: role:u32
        assert_eq!(size_of::<transport::DatagramHead>(), 8);
        assert_eq!(size_of::<transport::EventHead>(), 4);
        assert_eq!(size_of::<transport::OfferHead>(), 4);
    }

    #[test]
    fn the_table_indexes_are_the_contracts_slots() {
        assert_eq!(
            [
                store::READ,
                store::SCAN,
                store::COMMIT,
                store::CLOCK,
                store::INFO
            ],
            [0, 1, 2, 3, 4]
        );
        assert_eq!(secret::RESOLVE, 0);
        assert_eq!(
            [
                auth::VERIFY,
                auth::VERIFY_IO,
                auth::LOGIN,
                auth::OUTBOUND,
                auth::REFRESH,
                auth::SERVE
            ],
            [0, 1, 2, 3, 4, 5]
        );
        assert_eq!([hook::ON, hook::ON_IO], [0, 1]);
        assert_eq!(
            [export::DELIVER, export::RENDER, export::CONFIRM],
            [0, 1, 2]
        );
        assert_eq!(
            [
                plane::REQUEST,
                plane::UPSTREAM,
                plane::PIECE,
                plane::END,
                plane::REWRITE,
                plane::RENDER,
                plane::ADMIN,
                plane::PROBE,
                plane::DEMUX,
                plane::SELECT_RESOURCES,
                plane::CHANNEL
            ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        );
        assert_eq!(
            [
                transport::BEGIN,
                transport::INGEST,
                transport::EMIT,
                transport::TIMER,
                transport::DATAGRAM,
                transport::EVENT,
                transport::OFFER
            ],
            [0, 1, 2, 3, 4, 5, 6]
        );
    }

    /// The method bit of a kind's D_METHODS is `1 << slot`: the index the watchdog names an entry by is
    /// the index the crossing place calls.
    #[test]
    fn a_method_bit_is_one_shifted_by_its_slot() {
        use busbar_plugin_abi::{auth as a, plane as p, transport as t};
        assert_eq!(1u64 << auth::SERVE, a::M_SERVE);
        assert_eq!(1u64 << auth::VERIFY_IO, a::M_VERIFY_IO);
        assert_eq!(1u64 << plane::CHANNEL, p::M_CHANNEL);
        assert_eq!(1u64 << plane::DEMUX, p::M_DEMUX);
        assert_eq!(1u64 << transport::EMIT, t::M_EMIT);
        assert_eq!(1u64 << transport::OFFER, t::M_OFFER);
    }
}
