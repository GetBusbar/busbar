// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The vocabularies two or three kinds share (interface revision C.5), each a **versioned module** with its
//! own wire fingerprint, outside the core fingerprint.
//!
//! Some record sets cross between kinds through the engine: request and response heads (plane and
//! transport), verified identity (written by auth, read by plane and hook), the conversation (plane to
//! hook), the route record (plane, export, hook). A kind contract states which vocabulary versions it uses
//! (a `USES_*` line in its `consts`, which is in its fingerprint). Changing a vocabulary is a new module
//! beside the old one (`head2` beside `head1`); each kind adopts it in its own next version, and the
//! fingerprints of kinds that do not use it do not move. A module is deleted only when no supported kind
//! version uses it.
//!
//! `net1` (the network steps OPEN, STARTTLS, WRITE, READ, CLOSE, FETCH), `records1` (the record store step)
//! and `custody1` (the secret step) name the step sets of `crate::need` as they stand; their definitions
//! have not been lifted out of that file's block yet (see the revision's notes).

/// A vocabulary module's body: its items unchanged, their wire text, and the fingerprint of that text
/// (names, numbers, field types and order; comments are not hashed, `crate::fp`).
macro_rules! vocab {
    ($($item:tt)*) => {
        $($item)*
        /// This vocabulary version's wire text.
        pub const TEXT: &str = stringify!($($item)*);
        /// This vocabulary version's wire fingerprint.
        pub const FP: u64 = $crate::fp::fp(TEXT.as_bytes());
    };
}

/// Head records, version 1: HTTP-like request and response heads, shared by plane and transport.
pub mod head1 {
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    vocab! {
    /// The head tags (generic range; `records::tag` re-exports them under their frozen paths).
    pub mod tag {
        pub const H_METHOD: u16 = 0x0020; // TEXT shape
        pub const H_PATH: u16 = 0x0021; // TEXT shape, path + query as received
        pub const H_AUTHORITY: u16 = 0x0022; // TEXT shape
        pub const H_SCHEME: u16 = 0x0023; // TEXT shape
        pub const H_STATUS: u16 = 0x0024; // Pod U32Rec
        /// Engine-written only, last in a ROLE_CLIENT `emit` head: H_BUDGET_NS = the request's remaining
        /// deadline in ns at the emit (≥ 1; absent = no deadline); H_BODY_LEN = the body's total length when
        /// the engine holds it before the head goes (absent = streamed). Anywhere else a plugin sees neither.
        pub const H_BUDGET_NS: u16 = 0x0025;
        pub const H_BODY_LEN: u16 = 0x0026; // Pod U64Rec each
        /// Engine-written only, in a ROLE_CLIENT `emit` head, beside H_BUDGET_NS and H_BODY_LEN (a plane
        /// never receives a client head, so it never sees them). SealedPairRec + the name. A header whose
        /// value the engine holds sealed: the transport is told the name and the value's length, never the
        /// value. The record's position among the head's H_SEALED_* records, from 0, is its slot; the
        /// transport marks where the bytes go with a transport WIRE_SEALED for that slot, and the engine
        /// writes them there. A transport that declares FB_CLIENT accepts these and covers every slot.
        pub const H_SEALED_PAIR: u16 = 0x0027;
        /// The same for a query pair `name=<slot k, len bytes>` the transport appends to H_PATH's target,
        /// in record order, before any fragment. The name is percent-encoded by the engine.
        pub const H_SEALED_QUERY: u16 = 0x0028;
    }

    /// The fixed part of H_SEALED_PAIR and H_SEALED_QUERY. Tail = the name, `name_len` bytes. `len` = the
    /// sealed value's length in bytes as it will stand on the wire. No value bytes, ever.
    #[repr(C)]
    #[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
    pub struct SealedPairRec {
        pub name_len: u32,
        pub len: u32,
    }
    }
    impl crate::records::Pod for SealedPairRec {}
}

/// Verified identity, version 1: written by auth, read by plane (`PlaneReq.identity`) and hook. One
/// ID_SUBJECT (text), then ID_GROUP* (text), then ID_CLAIM* (pair shape).
pub mod identity1 {
    vocab! {
    pub mod tag {
        pub const ID_SUBJECT: u16 = 0x0050;
        pub const ID_GROUP: u16 = 0x0051;
        pub const ID_CLAIM: u16 = 0x0052;
    }
    }
}

/// The dialect-neutral conversation, version 1: produced by planes and read by hooks (and the REWRITE a hook
/// returns, consumed by the plane). UTF-8 JSON, exactly this shape:
/// `{"system": string?, "messages": [{"role": string, "content": string | array}], "tools": [object]?}`.
pub mod conversation1 {
    vocab! {
    pub mod tag {
        pub const CONVERSATION: u16 = 0x0030;
    }
    }
}

/// The network steps, version 1 (OPEN, STARTTLS, WRITE, READ, CLOSE, FETCH): store, auth, export, hook,
/// secret. The step numbers and records are `crate::need`'s; this module names the set and its one addition.
pub mod net1 {
    pub use crate::need::op::{CLOSE, FETCH, OPEN, READ, STARTTLS, WRITE};
    vocab! {
    /// FETCH flag: "status only, discard the body". The engine reads and discards the response body and
    /// answers the status and headers with an empty body, whatever the body's size. A sink whose receiver
    /// answers a large body is thereby delivered once, not resent for ever against the answer limit.
    pub const FETCH_STATUS_ONLY: u32 = 1 << 24;
    }
}

/// The route records, version 1: what a plugin declares to mount a route. Used by plane, export and hook
/// routes (export and hook: no ROUTE_* class bit, who within public, principal, operator, scope none,
/// money none).
///
/// **Per route: one route item and one admission item, every field stated, no default.** A route without
/// its admission item, a zero or unknown value in a stated field, or a breach of a load rule below refuses
/// the plugin at load, naming the route. That is what makes an unadmitted route impossible to mount: it
/// cannot be declared.
pub mod route1 {
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    vocab! {
    /// The body of a route describe item (the plane's D_ROUTE). Tail = the path pattern text
    /// (`/v1/chat/completions`, `/mcp`, `{*rest}` wildcard). `flags` = the route's class: no bit (a data
    /// route) or exactly one ROUTE_* bit. `auth` = who may call: a non-empty set of WHO_* (the plane's
    /// AUTH_* numbers).
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
    pub struct RouteRec {
        pub route: u32,
        pub methods: u32,
        pub flags: u32,
        pub auth: u32,
    }
    /// The body of a route admission item (the plane's D_ROUTE_ADMISSION): exactly one per route item,
    /// keyed by `route`. Tail = the kind the walk is judged under (`pool`, `mcp_server`, `agent`), present
    /// exactly when `scope` holds SCOPE_WALK. The kinds of SCOPE_SELECTED are the route's resource item.
    /// A record never grows: a new field is a new vocabulary version.
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
    pub struct RouteAdmissionRec {
        /// The route item this admits.
        pub route: u32,
        /// What the key is judged against: SCOPE_NONE, said outright; or SCOPE_WALK, SCOPE_SELECTED or both.
        pub scope: u32,
        /// Whether money moves: MONEY_NONE or MONEY_UNIT.
        pub money: u32,
        /// Whether the route keeps state per caller: CALLERS_SHARED or CALLERS_DISTINCT.
        pub callers: u32,
    }

    /// RouteRec.flags, the class: none of these is a data route; at most one may be set.
    pub const ROUTE_CATALOG: u32 = 1;
    pub const ROUTE_ADMIN: u32 = 2;
    pub const ROUTE_LINE: u32 = 4;
    pub const ROUTE_RECOVERY: u32 = 8;
    pub const ROUTE_UPGRADE: u32 = 16;
    pub const ROUTE_ALL: u32 = 31;

    /// RouteRec.auth: the numbers of the plane's AUTH_* classes.
    pub const WHO_PRINCIPAL: u32 = 1;
    pub const WHO_OPTIONAL: u32 = 2;
    pub const WHO_PUBLIC: u32 = 4;
    pub const WHO_TICKET: u32 = 8;
    pub const WHO_SIGNED_INGRESS: u32 = 16;
    pub const WHO_OPERATOR: u32 = 32;
    pub const WHO_ALL: u32 = 63;
    /// The members of "who" that yield a principal (a route on which money moves admits only these).
    pub const WHO_YIELDS_PRINCIPAL: u32 = WHO_PRINCIPAL | WHO_TICKET;

    pub const SCOPE_NONE: u32 = 1;
    pub const SCOPE_WALK: u32 = 2;
    pub const SCOPE_SELECTED: u32 = 4;

    pub const MONEY_NONE: u32 = 1;
    pub const MONEY_UNIT: u32 = 2;

    pub const CALLERS_SHARED: u32 = 1;
    pub const CALLERS_DISTINCT: u32 = 2;

    /// The longest challenge text (the `WWW-Authenticate` parameter a protocol's specification requires).
    pub const CHALLENGE_MAX: usize = 256;
    }
    impl crate::records::Pod for RouteRec {}
    impl crate::records::Pod for RouteAdmissionRec {}

    /// What the declaring image has, as far as the route rules need to know.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
    pub struct Has {
        /// The image declares `render`.
        pub render: bool,
        /// The image declares `select_resources`.
        pub select_resources: bool,
        /// The image declares `upstream`.
        pub upstream: bool,
        /// How many resource kinds the route names for SCOPE_SELECTED.
        pub selected_kinds: usize,
        /// Whether the admission item carried a walk kind (a non-empty tail).
        pub walk_kind: bool,
        /// The bit of GET in the route's method mask (an upgrade route is GET only); 0 = not checked here.
        pub method_get: u32,
    }

    /// Why a route refuses its plugin at load. The loader's text names the route and this.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum RouteFault {
        /// The route has no admission item.
        NoAdmission,
        /// A field is zero (not stated) or holds a value this version does not define: its name.
        Field(&'static str),
        /// More than one ROUTE_* class bit.
        ClassNotAlone,
        /// SCOPE_NONE together with a walk or a selection.
        ScopeNoneWithOthers,
        /// A public or optional caller on a route with a scope or with money.
        OpenCallerScopedOrBilled,
        /// A catalog route that is not exactly: the walk, no money, and an image with `render`.
        Catalog,
        /// SCOPE_SELECTED without `select_resources` or without a named kind.
        Selected,
        /// SCOPE_WALK without `upstream` or without the kind the walk is judged under.
        Walk,
        /// A walk kind stated without SCOPE_WALK.
        WalkKindWithoutWalk,
        /// Money on a route some member of whose "who" yields no principal.
        MoneyWithoutPrincipal,
        /// WHO_OPERATOR and ROUTE_ADMIN do not go together (each requires the other).
        OperatorAdmin,
        /// An upgrade route whose methods are not exactly GET.
        UpgradeNotGet,
    }

    /// The load rules of one route (`DESIGN-inbound-admission.md` C5). The engine's loader and the
    /// conformance suite call this one function, so they cannot disagree on what may be mounted.
    pub const fn check(
        route: &RouteRec,
        admission: Option<&RouteAdmissionRec>,
        has: Has,
    ) -> Result<(), RouteFault> {
        let Some(adm) = admission else {
            return Err(RouteFault::NoAdmission);
        };
        if adm.route != route.route {
            return Err(RouteFault::Field("route"));
        }
        if route.methods == 0 {
            return Err(RouteFault::Field("methods"));
        }
        if route.flags & !ROUTE_ALL != 0 {
            return Err(RouteFault::Field("flags"));
        }
        if route.flags.count_ones() > 1 {
            return Err(RouteFault::ClassNotAlone);
        }
        if route.auth == 0 || route.auth & !WHO_ALL != 0 {
            return Err(RouteFault::Field("auth"));
        }
        if adm.scope == 0 || adm.scope & !(SCOPE_NONE | SCOPE_WALK | SCOPE_SELECTED) != 0 {
            return Err(RouteFault::Field("scope"));
        }
        if adm.money != MONEY_NONE && adm.money != MONEY_UNIT {
            return Err(RouteFault::Field("money"));
        }
        if adm.callers != CALLERS_SHARED && adm.callers != CALLERS_DISTINCT {
            return Err(RouteFault::Field("callers"));
        }
        let none = adm.scope & SCOPE_NONE != 0;
        let walk = adm.scope & SCOPE_WALK != 0;
        let selected = adm.scope & SCOPE_SELECTED != 0;
        if none && (walk || selected) {
            return Err(RouteFault::ScopeNoneWithOthers);
        }
        if route.auth & (WHO_PUBLIC | WHO_OPTIONAL) != 0 && !(none && adm.money == MONEY_NONE) {
            return Err(RouteFault::OpenCallerScopedOrBilled);
        }
        if route.flags == ROUTE_CATALOG && !(walk && adm.money == MONEY_NONE && has.render) {
            return Err(RouteFault::Catalog);
        }
        if selected && !(has.select_resources && has.selected_kinds > 0) {
            return Err(RouteFault::Selected);
        }
        if walk && !(has.upstream && has.walk_kind) {
            return Err(RouteFault::Walk);
        }
        if !walk && has.walk_kind {
            return Err(RouteFault::WalkKindWithoutWalk);
        }
        if adm.money == MONEY_UNIT && route.auth & !WHO_YIELDS_PRINCIPAL != 0 {
            return Err(RouteFault::MoneyWithoutPrincipal);
        }
        if (route.auth & WHO_OPERATOR != 0) != (route.flags == ROUTE_ADMIN) {
            return Err(RouteFault::OperatorAdmin);
        }
        if route.flags == ROUTE_UPGRADE && has.method_get != 0 && route.methods != has.method_get {
            return Err(RouteFault::UpgradeNotGet);
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const DATA: RouteRec = RouteRec {
            route: 1,
            methods: 2,
            flags: 0,
            auth: WHO_PRINCIPAL,
        };
        const BILLED: RouteAdmissionRec = RouteAdmissionRec {
            route: 1,
            scope: SCOPE_WALK,
            money: MONEY_UNIT,
            callers: CALLERS_SHARED,
        };
        const PLANE: Has = Has {
            render: true,
            select_resources: false,
            upstream: true,
            selected_kinds: 0,
            walk_kind: true,
            method_get: 1,
        };

        #[test]
        fn a_route_mounts_only_with_its_admission_and_every_field_stated() {
            assert_eq!(check(&DATA, Some(&BILLED), PLANE), Ok(()));
            assert_eq!(check(&DATA, None, PLANE), Err(RouteFault::NoAdmission));
            for (field, adm) in [
                ("scope", RouteAdmissionRec { scope: 0, ..BILLED }),
                ("money", RouteAdmissionRec { money: 0, ..BILLED }),
                (
                    "callers",
                    RouteAdmissionRec {
                        callers: 0,
                        ..BILLED
                    },
                ),
                ("route", RouteAdmissionRec { route: 9, ..BILLED }),
            ] {
                assert_eq!(
                    check(&DATA, Some(&adm), PLANE),
                    Err(RouteFault::Field(field))
                );
            }
            assert_eq!(
                check(&RouteRec { auth: 0, ..DATA }, Some(&BILLED), PLANE),
                Err(RouteFault::Field("auth"))
            );
        }

        #[test]
        fn the_load_rules_refuse_what_they_name() {
            let bare = Has {
                walk_kind: false,
                ..PLANE
            };
            let public = RouteRec {
                auth: WHO_PUBLIC,
                ..DATA
            };
            let open = RouteAdmissionRec {
                scope: SCOPE_NONE,
                money: MONEY_NONE,
                ..BILLED
            };
            assert_eq!(check(&public, Some(&open), bare), Ok(()));
            assert_eq!(
                check(
                    &public,
                    Some(&RouteAdmissionRec {
                        money: MONEY_UNIT,
                        ..open
                    }),
                    bare
                ),
                Err(RouteFault::OpenCallerScopedOrBilled)
            );
            let catalog = RouteRec {
                flags: ROUTE_CATALOG,
                ..DATA
            };
            let free = RouteAdmissionRec {
                money: MONEY_NONE,
                ..BILLED
            };
            assert_eq!(check(&catalog, Some(&free), PLANE), Ok(()));
            assert_eq!(
                check(&catalog, Some(&BILLED), PLANE),
                Err(RouteFault::Catalog)
            );
            assert_eq!(
                check(
                    &DATA,
                    Some(&RouteAdmissionRec {
                        scope: SCOPE_SELECTED,
                        ..BILLED
                    }),
                    bare
                ),
                Err(RouteFault::Selected)
            );
            assert_eq!(check(&DATA, Some(&BILLED), bare), Err(RouteFault::Walk));
            assert_eq!(
                check(
                    &RouteRec {
                        auth: WHO_PRINCIPAL | WHO_SIGNED_INGRESS,
                        ..DATA
                    },
                    Some(&BILLED),
                    PLANE
                ),
                Err(RouteFault::MoneyWithoutPrincipal)
            );
            assert_eq!(
                check(
                    &RouteRec {
                        auth: WHO_OPERATOR,
                        ..DATA
                    },
                    Some(&free),
                    PLANE
                ),
                Err(RouteFault::OperatorAdmin)
            );
            assert_eq!(
                check(
                    &RouteRec {
                        flags: ROUTE_UPGRADE,
                        ..DATA
                    },
                    Some(&free),
                    PLANE
                ),
                Err(RouteFault::UpgradeNotGet)
            );
            assert_eq!(
                check(
                    &RouteRec {
                        flags: ROUTE_LINE | ROUTE_ADMIN,
                        ..DATA
                    },
                    Some(&free),
                    PLANE
                ),
                Err(RouteFault::ClassNotAlone)
            );
        }
    }
}
