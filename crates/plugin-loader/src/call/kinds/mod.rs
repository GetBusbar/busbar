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
                auth::LOGIN,
                auth::OUTBOUND,
                auth::REFRESH,
                auth::SERVE
            ],
            [0, 1, 2, 3, 4]
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
        use busbar_plugin_abi::auth as a;
        use busbar_plugin_abi::plane as p;
        use busbar_plugin_abi::transport as t;
        assert_eq!(1u64 << auth::SERVE, a::M_SERVE);
        assert_eq!(1u64 << plane::CHANNEL, p::M_CHANNEL);
        assert_eq!(1u64 << plane::DEMUX, p::M_DEMUX);
        assert_eq!(1u64 << transport::EMIT, t::M_EMIT);
        assert_eq!(1u64 << transport::OFFER, t::M_OFFER);
    }
}

/// SIDE BY SIDE with the contract's own packers. The contract crate generates, from each kind's
/// declaration, the host's half of every method (`<kind>::pack::<method>`) and each method's table
/// position (`<kind>::slot::<method>`). These tests build the same call both ways from the same
/// arguments and require the two to be one call: the same head bytes, and the same lent memory in every
/// text and blob position. A face that drifts from the contract fails here, with no plugin and no
/// engine.
#[cfg(test)]
mod against_the_contract {
    use super::*;
    use crate::call::frame::{Frame, Head, Mono};
    use crate::call::Call;
    use busbar_plugin_abi::types::{Bytes, Pair, Slice, Str};

    /// The two calls are one call: equal heads, and position by position the same address and length.
    fn same(mine: &Call<'_>, theirs: &Call<'_>) {
        assert_eq!(mine.head(), theirs.head(), "head");
        assert_eq!(mine.mono_ns(), theirs.mono_ns(), "mono_ns");
        assert_eq!(mine.texts().len(), theirs.texts().len(), "texts");
        for (at, (a, b)) in mine.texts().iter().zip(theirs.texts()).enumerate() {
            assert!(
                core::ptr::eq(a.get().as_ptr(), b.get().as_ptr()),
                "text {at}"
            );
            assert_eq!(a.len(), b.len(), "text {at}");
        }
        assert_eq!(mine.blobs().len(), theirs.blobs().len(), "blobs");
        for (at, (a, b)) in mine.blobs().iter().zip(theirs.blobs()).enumerate() {
            assert!(
                core::ptr::eq(a.get().as_ptr(), b.get().as_ptr()),
                "blob {at}"
            );
            assert_eq!(a.len(), b.len(), "blob {at}");
        }
    }

    /// My frame against the contract's packer, at one clock reading.
    fn check<H: Head, const T: usize, const B: usize>(
        frame: &Frame<'_, H, T, B>,
        theirs: impl FnOnce(u64, &mut dyn FnMut(&Call<'_>)),
    ) {
        let mine = frame.call(Mono(77));
        let mut crossed = 0;
        theirs(77, &mut |call: &Call<'_>| {
            crossed += 1;
            same(&mine, call);
        });
        assert_eq!(crossed, 1, "the contract's packer crossed once");
    }

    #[test]
    fn the_slots_are_the_contracts() {
        use busbar_plugin_abi::{
            auth as a, export as x, hook as h, plane as p, secret as s, store as st, transport as t,
        };
        let u = usize::from;
        assert_eq!(
            [
                u(store::READ),
                u(store::SCAN),
                u(store::COMMIT),
                u(store::CLOCK),
                u(store::INFO)
            ],
            [
                st::slot::read,
                st::slot::scan,
                st::slot::commit,
                st::slot::clock,
                st::slot::info
            ]
        );
        assert_eq!(u(secret::RESOLVE), s::slot::resolve);
        assert_eq!(
            [
                u(auth::VERIFY),
                u(auth::LOGIN),
                u(auth::OUTBOUND),
                u(auth::REFRESH),
                u(auth::SERVE)
            ],
            [
                a::slot::verify,
                a::slot::login,
                a::slot::outbound,
                a::slot::refresh,
                a::slot::serve
            ]
        );
        assert_eq!([u(hook::ON), u(hook::ON_IO)], [h::slot::on, h::slot::on_io]);
        assert_eq!(
            [u(export::DELIVER), u(export::RENDER), u(export::CONFIRM)],
            [x::slot::deliver, x::slot::render, x::slot::confirm]
        );
        assert_eq!(
            [
                u(plane::REQUEST),
                u(plane::UPSTREAM),
                u(plane::PIECE),
                u(plane::END),
                u(plane::REWRITE),
                u(plane::RENDER),
                u(plane::ADMIN),
                u(plane::PROBE),
                u(plane::DEMUX),
                u(plane::SELECT_RESOURCES),
                u(plane::CHANNEL)
            ],
            [
                p::slot::request,
                p::slot::upstream,
                p::slot::piece,
                p::slot::end,
                p::slot::rewrite,
                p::slot::render,
                p::slot::admin,
                p::slot::probe,
                p::slot::demux,
                p::slot::select_resources,
                p::slot::channel
            ]
        );
        assert_eq!(
            [
                u(transport::BEGIN),
                u(transport::INGEST),
                u(transport::EMIT),
                u(transport::TIMER),
                u(transport::DATAGRAM),
                u(transport::EVENT),
                u(transport::OFFER)
            ],
            [
                t::slot::begin,
                t::slot::ingest,
                t::slot::emit,
                t::slot::timer,
                t::slot::datagram,
                t::slot::event,
                t::slot::offer
            ]
        );
        // And the loader's own table of the 34 methods names them as the contract does.
        for (kind, names) in [
            (busbar_plugin_abi::types::KindCode::Store, &st::METHODS[..]),
            (busbar_plugin_abi::types::KindCode::Secret, &s::METHODS[..]),
            (busbar_plugin_abi::types::KindCode::Auth, &a::METHODS[..]),
            (busbar_plugin_abi::types::KindCode::Hook, &h::METHODS[..]),
            (busbar_plugin_abi::types::KindCode::Export, &x::METHODS[..]),
            (busbar_plugin_abi::types::KindCode::Plane, &p::METHODS[..]),
            (
                busbar_plugin_abi::types::KindCode::Transport,
                &t::METHODS[..],
            ),
        ] {
            for (slot, name) in names.iter().enumerate() {
                let row = crate::call::layout::method(kind, slot as u8).expect("a row");
                assert_eq!(row.name, *name, "{} slot {slot}", kind.word());
                assert_eq!(crate::watchdog::entry_name(kind, slot as u8), *name);
            }
            assert!(crate::call::layout::method(kind, names.len() as u8).is_none());
        }
    }

    fn headers() -> [Pair<'static>; 2] {
        [
            Pair {
                name: Str::new("accept"),
                value: Bytes::new(b"*/*"),
            },
            Pair {
                name: Str::new("x-request"),
                value: Bytes::new(b"7"),
            },
        ]
    }

    #[test]
    fn auth_verify_is_the_contracts_call() {
        let headers = headers();
        let req = busbar_plugin_abi::auth::AuthReq {
            flags: busbar_plugin_abi::auth::REQ_ISSUED_LOOKED_UP,
            _r: 0,
            method: Str::new("POST"),
            path: Str::new("/v1/chat"),
            query: Str::new("a=b"),
            authority: Str::new("gw.example"),
            headers: Slice::new(&headers),
            peer: Str::new("10.0.0.9:443"),
            tls_peer_cert: Bytes::new(b"cert"),
            body: Bytes::new(b"body"),
            issued: Bytes::new(b"issued"),
            now_s: 1_800_000_000,
        };
        check(&auth::verify_frame(&req), |at, cross| {
            busbar_plugin_abi::auth::pack::verify(at, &req, |call| cross(call));
        });
    }

    fn plane_req<'a>(headers: &'a [Pair<'a>]) -> busbar_plugin_abi::plane::PlaneReq<'a> {
        busbar_plugin_abi::plane::PlaneReq {
            route: 3,
            flags: 1,
            auth: 2,
            _r: 0,
            method: Str::new("POST"),
            path: Str::new("/v1/messages"),
            query: Str::new(""),
            headers: Slice::new(headers),
            identity: Bytes::new(b"identity-records"),
            request_id: 0x0102_0304_0506_0708,
            carrier: 9,
            work: Str::new("work-1"),
            ticket_record: Bytes::new(b"ticket"),
        }
    }

    #[test]
    fn plane_request_render_and_select_are_the_contracts_calls() {
        let headers = headers();
        let req = plane_req(&headers);
        let body = b"{\"model\":\"m\"}";
        check(&plane::request_frame(&req, body), |at, cross| {
            busbar_plugin_abi::plane::pack::request(at, &req, Bytes::new(body), |call| cross(call));
        });
        check(&plane::render_frame(&req, 4, body), |at, cross| {
            busbar_plugin_abi::plane::pack::render(at, &req, 4, Bytes::new(body), |call| {
                cross(call)
            });
        });
        check(&plane::select_frame(2, &req, body), |at, cross| {
            busbar_plugin_abi::plane::pack::select_resources(
                at,
                2,
                &req,
                Bytes::new(body),
                |call| cross(call),
            );
        });
    }

    #[test]
    fn plane_target_calls_are_the_contracts_calls() {
        let params = headers();
        let target = busbar_plugin_abi::plane::Target {
            attempt: 2,
            flags: 1,
            dialect: Str::new("openai"),
            model: Str::new("m"),
            base_path: Str::new("/v1"),
            upstream: Str::new("primary"),
            provider: Str::new("mock"),
            params: Slice::new(&params),
            admission: Bytes::new(b"admission"),
        };
        let frame = plane::target_frame(&target);
        check(&frame, |at, cross| {
            busbar_plugin_abi::plane::pack::upstream(at, &target, |call| cross(call));
        });
        check(&frame, |at, cross| {
            busbar_plugin_abi::plane::pack::probe(at, &target, |call| cross(call));
        });
        check(&frame, |at, cross| {
            busbar_plugin_abi::plane::pack::channel(at, &target, |call| cross(call));
        });
    }

    #[test]
    fn plane_piece_and_demux_are_the_contracts_calls() {
        let bytes = b"chunk";
        let head = plane::PieceHead {
            from: 1,
            exchange: 2,
            flags: 4,
        };
        check(&Frame::new(head, [], [bytes.as_slice()]), |at, cross| {
            busbar_plugin_abi::plane::pack::piece(at, 1, 2, 4, Bytes::new(bytes), |call| {
                cross(call)
            });
        });
        let key = "session-key";
        check(&Frame::new((), [key], [bytes.as_slice()]), |at, cross| {
            busbar_plugin_abi::plane::pack::demux(at, Str::new(key), Bytes::new(bytes), |call| {
                cross(call)
            });
        });
    }

    #[test]
    fn transport_begin_and_emit_are_the_contracts_calls() {
        let conn = busbar_plugin_abi::transport::ConnInfo {
            role: busbar_plugin_abi::transport::ROLE_SERVER,
            flags: busbar_plugin_abi::transport::CONN_ACCEPT,
            alpn: Str::new("h2"),
            sni: Str::new("gw.example"),
            peer: Str::new("10.0.0.9:51000"),
            local: Str::new("10.0.0.1:443"),
            tls_peer_cert: Bytes::new(b"cert"),
            leftover: Bytes::new(b"PRI * HTTP/2.0"),
            head: Bytes::new(b""),
            local_fingerprint: Str::new("sha256:ab"),
            mono_ns: 77,
        };
        check(&transport::begin_frame(&conn), |at, cross| {
            busbar_plugin_abi::transport::pack::begin(at, &conn, |call| cross(call));
        });
        // A whole small answer in one call: head, body and the end.
        use busbar_plugin_abi::transport::{E_BODY, E_END, E_HEAD};
        let (head, body) = (b"head-records".as_slice(), b"payload".as_slice());
        let parts = transport::Pieces {
            head: Some(head),
            body: Some(body),
            trailers: None,
            end: Some(&[]),
            refuse: None,
        };
        let lent = [
            Bytes::new(head),
            Bytes::new(body),
            Bytes::new(parts.end.unwrap()),
        ];
        let pieces = E_HEAD | E_BODY | E_END;
        check(
            &transport::emit_frame(5, pieces, 0, 0, parts),
            |at, cross| {
                busbar_plugin_abi::transport::pack::emit(
                    at,
                    5,
                    pieces,
                    0,
                    0,
                    Slice::new(&lent),
                    |call| cross(call),
                );
            },
        );
        // Credit alone: no blob.
        let consumed = busbar_plugin_abi::transport::E_CONSUMED;
        check(
            &transport::emit_frame(5, consumed, 0, 4096, transport::Pieces::default()),
            |at, cross| {
                busbar_plugin_abi::transport::pack::emit(
                    at,
                    5,
                    consumed,
                    0,
                    4096,
                    Slice::new(&[]),
                    |call| cross(call),
                );
            },
        );
    }

    #[test]
    fn the_one_number_heads_are_the_contracts_calls() {
        let bytes = b"records";
        check(
            &Frame::new(hook::PointHead { point: 3 }, [], [bytes.as_slice()]),
            |at, cross| {
                busbar_plugin_abi::hook::pack::on(at, 3, Bytes::new(bytes), |call| cross(call));
            },
        );
        check(
            &Frame::new(export::ScopeHead { scope: 2 }, [], [bytes.as_slice()]),
            |at, cross| {
                busbar_plugin_abi::export::pack::render(at, 2, Bytes::new(bytes), |call| {
                    cross(call)
                });
            },
        );
        let deliver = export::DeliverHead {
            stream: 4,
            _gap: 0,
            delivery: 0x1122_3344_5566_7788,
            attempt: 2,
            lines: 9,
        };
        check(&Frame::new(deliver, [], [bytes.as_slice()]), |at, cross| {
            busbar_plugin_abi::export::pack::deliver(
                at,
                4,
                0x1122_3344_5566_7788,
                2,
                9,
                Bytes::new(bytes),
                |call| cross(call),
            );
        });
        check(
            &Frame::new(export::ConfirmHead { delivery: 8 }, [], []),
            |at, cross| {
                busbar_plugin_abi::export::pack::confirm(at, 8, |call| cross(call));
            },
        );
        check(
            &Frame::new(transport::OfferHead { role: 1 }, [], []),
            |at, cross| {
                busbar_plugin_abi::transport::pack::offer(at, 1, |call| cross(call));
            },
        );
        check(
            &Frame::new(
                transport::DatagramHead { path: 6, flags: 1 },
                [],
                [bytes.as_slice()],
            ),
            |at, cross| {
                busbar_plugin_abi::transport::pack::datagram(at, 6, 1, Bytes::new(bytes), |call| {
                    cross(call)
                });
            },
        );
        check(
            &Frame::new(plane::AdminHead { op: 5 }, [], [bytes.as_slice()]),
            |at, cross| {
                busbar_plugin_abi::plane::pack::admin(at, 5, Bytes::new(bytes), |call| cross(call));
            },
        );
        check(
            &Frame::new(auth::LoginHead { step: 2 }, [], [bytes.as_slice()]),
            |at, cross| {
                busbar_plugin_abi::auth::pack::login(at, 2, Bytes::new(bytes), |call| cross(call));
            },
        );
        check(&Frame::new((), [], [bytes.as_slice()]), |at, cross| {
            busbar_plugin_abi::secret::pack::resolve(at, Bytes::new(bytes), |call| cross(call));
        });
        check(&Frame::new((), [], []), |at, cross| {
            busbar_plugin_abi::store::pack::info(at, |call| cross(call));
        });
    }
}
