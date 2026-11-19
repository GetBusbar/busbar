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

/// The route record, version 1: what a plugin declares to mount a route. Used by plane, export and hook
/// routes (export and hook: class data, who within public, principal, operator, scope none, money none).
///
/// **One record per route, every field stated, no default.** A zero in any stated field, an unknown value,
/// or a breach of a load rule below refuses the plugin at load, naming the route. That is what makes an
/// unadmitted route impossible to mount: it cannot be declared.
pub mod route1 {
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    vocab! {
    /// The body of a route describe item. Tail = nested generic TEXT records, in order: the path pattern
    /// (`/v1/chat/completions`, `/mcp`, `{*rest}` wildcard); then, exactly when `scope` holds SCOPE_WALK, the
    /// kind the walk is judged under (`pool`, `mcp_server`, `agent`). The kinds of SCOPE_SELECTED are the
    /// route's resource item; the credential header and the optional challenge are items of their own,
    /// keyed by `route`. A record never grows: a new field is a new vocabulary version.
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
    pub struct RouteRec {
        /// The route's id, unique within the image.
        pub route: u32,
        /// The method mask.
        pub methods: u32,
        /// One CLASS_* word (not bits): which sequence the engine runs.
        pub class: u32,
        /// Who may call: a non-empty set of WHO_*.
        pub who: u32,
        /// What the key is judged against: SCOPE_NONE, said outright; or SCOPE_WALK, SCOPE_SELECTED or both.
        pub scope: u32,
        /// Whether money moves: MONEY_NONE or MONEY_UNIT.
        pub money: u32,
        /// Whether the route keeps state per caller: STATE_SHARED or STATE_DISTINCT.
        pub state: u32,
        pub _r: u32,
    }

    pub const CLASS_DATA: u32 = 1;
    pub const CLASS_CATALOG: u32 = 2;
    pub const CLASS_ADMIN: u32 = 3;
    pub const CLASS_LINE: u32 = 4;
    pub const CLASS_RECOVERY: u32 = 5;
    pub const CLASS_UPGRADE: u32 = 6;

    /// The numbers of the plane's AUTH_* classes, which `PlaneReq.auth` carries one of.
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

    pub const STATE_SHARED: u32 = 1;
    pub const STATE_DISTINCT: u32 = 2;

    /// The method bit of GET in `methods` (an upgrade route is GET only).
    pub const METHOD_GET: u32 = 1;
    /// The longest challenge text (the `WWW-Authenticate` parameter a protocol's specification requires).
    pub const CHALLENGE_MAX: usize = 256;
    }
    impl crate::records::Pod for RouteRec {}

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
        /// Whether the route's record carried a walk kind (a non-empty second TEXT).
        pub walk_kind: bool,
    }

    /// Why a route record refuses its plugin at load. The loader's text names the route and this.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum RouteFault {
        /// A field is zero (not stated) or holds a value this version does not define: its name.
        Field(&'static str),
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
        /// WHO_OPERATOR and CLASS_ADMIN do not go together (each requires the other).
        OperatorAdmin,
        /// An upgrade route whose methods are not exactly GET.
        UpgradeNotGet,
    }

    /// The load rules of one route record (`DESIGN-inbound-admission.md` C5). The engine's loader and the
    /// conformance suite call this one function, so they cannot disagree on what may be mounted.
    pub const fn check(rec: &RouteRec, has: Has) -> Result<(), RouteFault> {
        if rec.methods == 0 {
            return Err(RouteFault::Field("methods"));
        }
        if rec.class < CLASS_DATA || rec.class > CLASS_UPGRADE {
            return Err(RouteFault::Field("class"));
        }
        if rec.who == 0 || rec.who & !WHO_ALL != 0 {
            return Err(RouteFault::Field("who"));
        }
        if rec.scope == 0 || rec.scope & !(SCOPE_NONE | SCOPE_WALK | SCOPE_SELECTED) != 0 {
            return Err(RouteFault::Field("scope"));
        }
        if rec.money != MONEY_NONE && rec.money != MONEY_UNIT {
            return Err(RouteFault::Field("money"));
        }
        if rec.state != STATE_SHARED && rec.state != STATE_DISTINCT {
            return Err(RouteFault::Field("state"));
        }
        if rec._r != 0 {
            return Err(RouteFault::Field("_r"));
        }
        let none = rec.scope & SCOPE_NONE != 0;
        let walk = rec.scope & SCOPE_WALK != 0;
        let selected = rec.scope & SCOPE_SELECTED != 0;
        if none && (walk || selected) {
            return Err(RouteFault::ScopeNoneWithOthers);
        }
        if rec.who & (WHO_PUBLIC | WHO_OPTIONAL) != 0 && !(none && rec.money == MONEY_NONE) {
            return Err(RouteFault::OpenCallerScopedOrBilled);
        }
        if rec.class == CLASS_CATALOG && !(walk && rec.money == MONEY_NONE && has.render) {
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
        if rec.money == MONEY_UNIT && rec.who & !WHO_YIELDS_PRINCIPAL != 0 {
            return Err(RouteFault::MoneyWithoutPrincipal);
        }
        if (rec.who & WHO_OPERATOR != 0) != (rec.class == CLASS_ADMIN) {
            return Err(RouteFault::OperatorAdmin);
        }
        if rec.class == CLASS_UPGRADE && rec.methods != METHOD_GET {
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
            class: CLASS_DATA,
            who: WHO_PRINCIPAL,
            scope: SCOPE_WALK,
            money: MONEY_UNIT,
            state: STATE_SHARED,
            _r: 0,
        };
        const PLANE: Has = Has {
            render: true,
            select_resources: false,
            upstream: true,
            selected_kinds: 0,
            walk_kind: true,
        };

        #[test]
        fn a_stated_data_route_mounts_and_a_missing_field_does_not() {
            assert_eq!(check(&DATA, PLANE), Ok(()));
            for (field, rec) in [
                ("class", RouteRec { class: 0, ..DATA }),
                ("who", RouteRec { who: 0, ..DATA }),
                ("scope", RouteRec { scope: 0, ..DATA }),
                ("money", RouteRec { money: 0, ..DATA }),
                ("state", RouteRec { state: 0, ..DATA }),
            ] {
                assert_eq!(check(&rec, PLANE), Err(RouteFault::Field(field)));
            }
        }

        #[test]
        fn the_load_rules_refuse_what_they_name() {
            let public = RouteRec {
                who: WHO_PUBLIC,
                scope: SCOPE_NONE,
                money: MONEY_NONE,
                ..DATA
            };
            let bare = Has {
                walk_kind: false,
                ..PLANE
            };
            assert_eq!(check(&public, bare), Ok(()));
            assert_eq!(
                check(
                    &RouteRec {
                        money: MONEY_UNIT,
                        ..public
                    },
                    bare
                ),
                Err(RouteFault::OpenCallerScopedOrBilled)
            );
            let catalog = RouteRec {
                class: CLASS_CATALOG,
                money: MONEY_NONE,
                ..DATA
            };
            assert_eq!(check(&catalog, PLANE), Ok(()));
            assert_eq!(
                check(
                    &RouteRec {
                        money: MONEY_UNIT,
                        ..catalog
                    },
                    PLANE
                ),
                Err(RouteFault::Catalog)
            );
            assert_eq!(
                check(
                    &RouteRec {
                        scope: SCOPE_SELECTED,
                        ..DATA
                    },
                    bare
                ),
                Err(RouteFault::Selected)
            );
            assert_eq!(check(&DATA, bare), Err(RouteFault::Walk));
            assert_eq!(
                check(
                    &RouteRec {
                        who: WHO_PRINCIPAL | WHO_SIGNED_INGRESS,
                        ..DATA
                    },
                    PLANE
                ),
                Err(RouteFault::MoneyWithoutPrincipal)
            );
            assert_eq!(
                check(
                    &RouteRec {
                        who: WHO_OPERATOR,
                        money: MONEY_NONE,
                        ..DATA
                    },
                    PLANE
                ),
                Err(RouteFault::OperatorAdmin)
            );
            assert_eq!(
                check(
                    &RouteRec {
                        class: CLASS_UPGRADE,
                        ..DATA
                    },
                    PLANE
                ),
                Err(RouteFault::UpgradeNotGet)
            );
        }
    }
}
