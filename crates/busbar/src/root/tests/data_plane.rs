//! Tests for `data_plane.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.
//!
//! EVERY CELL HERE IS WRITTEN OVER A SURFACE THIS FILE DECLARES, not over a plane's. That is the
//! property under test: the chain builder is generic over the plane, so a cell that reached for a
//! real plane's surface would be proving that one plane works rather than that any plane does.

use super::*;

use busbar_contract::transport::surface::{
    Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   A SURFACE THAT IS NOBODY'S PLANE
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The transport this made-up protocol's document binding is served over.
const T_HTTP: &str = "http";

/// One mount, two addressed operations and one framed call — the smallest surface that still has
/// every shape the chain builder reads: a mount, a target template with a variable segment, an
/// exact target, and a document member.
const MOUNT: &str = "/made-up";

const D_ONE: &[Dispatch] = &[
    Dispatch::Target {
        path: "/made-up/things/{id}",
        method: "GET",
        bar: Bar::Credential,
    },
    Dispatch::Document {
        binding: "doc",
        method: "POST",
        member: "verb",
        name: "one",
        bar: Bar::Credential,
    },
];

const D_TWO: &[Dispatch] = &[Dispatch::Target {
    path: "/made-up/open",
    method: "GET",
    bar: Bar::Open,
}];

const SURFACE: WireSurface = WireSurface {
    bindings: &[BindingDecl {
        name: "doc",
        transport: T_HTTP,
        mounts: &[MOUNT],
    }],
    operations: &[
        Operation {
            op: "one",
            dispatch: D_ONE,
            answering: Answering::Unary,
            request_media: "application/json",
            response_media: "application/json",
        },
        Operation {
            op: "two",
            dispatch: D_TWO,
            answering: Answering::Unary,
            request_media: "application/json",
            response_media: "application/json",
        },
    ],
};

/// A surface whose one operation is addressed by nothing, which is the boot refusal `check_surface`
/// exists for. Declared here so the chain's own refusal has something real to refuse.
const UNADDRESSABLE: WireSurface = WireSurface {
    bindings: &[BindingDecl {
        name: "doc",
        transport: T_HTTP,
        mounts: &[MOUNT],
    }],
    operations: &[Operation {
        op: "nowhere",
        dispatch: &[],
        answering: Answering::Unary,
        request_media: "application/json",
        response_media: "application/json",
    }],
};

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE SURFACE IS CHECKED BEFORE A BYTE IS TAKEN
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **A chain over a surface that does not check REFUSES to exist.**
///
/// The check is the contract's own and is run HERE, at composition, rather than left to the first
/// request: an operation nothing addresses is a verb the deployment believes it serves and does not,
/// and the symptom of finding that out at request time is a 404 on a route the release notes list.
#[test]
fn a_surface_that_does_not_check_refuses_the_chain() {
    let refusal = PlaneChain::over(&UNADDRESSABLE).expect_err(
        "a surface whose operation is addressed by nothing must not compose a serving chain",
    );
    assert!(
        format!("{refusal}").contains("nowhere"),
        "the refusal must name the operation that cannot be reached, so an operator reads what to \
         fix rather than that something did not check: got `{refusal}`"
    );
}

/// **And a surface that checks composes.**
#[test]
fn a_surface_that_checks_composes_a_chain() {
    assert!(
        PlaneChain::over(&SURFACE).is_ok(),
        "the declared surface passes the contract's own check, so the chain must compose over it"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT THE CHAIN CLAIMS IS THE SURFACE'S OWN TABLE
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **Every address the surface declares is claimed, and the mount with them.**
///
/// Walked off the declaration rather than against a list here, so a protocol that gains an address
/// gains it here for free — which is the whole reason the chain takes a surface rather than a list
/// of paths.
#[test]
fn every_address_the_surface_declares_is_claimed() {
    let chain = PlaneChain::over(&SURFACE).expect("the declared surface checks");
    for (target, method) in [
        ("/made-up/things/an-identifier", "GET"),
        ("/made-up/open", "GET"),
        // The mount itself: the address the document binding is served on, which no target
        // template names and which a chain that read only templates would hand away.
        (MOUNT, "POST"),
    ] {
        assert!(
            chain.claims_the_target(target, method),
            "`{method} {target}` is declared by this surface and the chain did not claim it"
        );
    }
}

/// **And an address it does not declare is NOT claimed — including the near misses.**
///
/// The near misses are the cell. A prefix match would take `/made-uppermost`; a match that ignored
/// the method would take a `DELETE` of a `GET`-only address; and a match that treated a template as
/// a prefix would take a path with a segment too many.
#[test]
fn an_address_the_surface_does_not_declare_is_not_claimed() {
    let chain = PlaneChain::over(&SURFACE).expect("the declared surface checks");
    for (target, method) in [
        ("/made-uppermost", "GET"),
        ("/made-up/things/an-identifier/extra", "GET"),
        ("/made-up/things/an-identifier", "DELETE"),
        ("/somebody-else", "GET"),
    ] {
        assert!(
            !chain.claims_the_target(target, method),
            "`{method} {target}` is not an address this surface declares and the chain claimed it"
        );
    }
}

/// **A query string does not stop the mount matching.**
///
/// The contract's own `binding_at` cuts at the query and the fragment, and the chain inherits that
/// rather than re-deriving it: a mount that failed to match because a client appended a cache-buster
/// would answer around the loop for a well-formed request.
#[test]
fn the_mount_is_claimed_with_a_query_on_it() {
    let chain = PlaneChain::over(&SURFACE).expect("the declared surface checks");
    assert!(chain.claims_the_target("/made-up?x=1", "POST"));
    assert!(chain.claims_the_target("/made-up#frag", "POST"));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE AUDIENCE IS THE NODE'S DECLARED IDENTITY, JOINED TO THE PLANE'S OWN MOUNT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **The audience is `<public_url><mount>`, with the mount read off the surface.**
///
/// Neither half is written here: the identity is the deployment's and the mount is the protocol's,
/// so a plane that moved its mount moves the audience it demands and the audience it advertises
/// together. A constant in this file would be the third opinion.
#[test]
fn the_audience_joins_the_declared_identity_to_the_declared_mount() {
    let chain = PlaneChain::over(&SURFACE).expect("the declared surface checks");
    assert_eq!(
        chain.audience("https://gateway.example.com").as_deref(),
        Some("https://gateway.example.com/made-up")
    );
}

/// **A trailing slash, a path, a query and a fragment on the declared identity all resolve to ONE
/// audience.**
///
/// Every one of these is a legitimate spelling an operator writes, and every one of them names the
/// same node. A join that produced four different strings would be four different audiences: a
/// token minted against one would be refused at the door of another, and the only symptom is a
/// caller who cannot get in.
#[test]
fn the_audience_is_one_string_however_the_identity_was_spelled() {
    let chain = PlaneChain::over(&SURFACE).expect("the declared surface checks");
    for spelling in [
        "https://gateway.example.com",
        "https://gateway.example.com/",
        "https://gateway.example.com/ignored/path",
        "https://gateway.example.com/?query=1",
        "https://gateway.example.com/#fragment",
    ] {
        assert_eq!(
            chain.audience(spelling).as_deref(),
            Some("https://gateway.example.com/made-up"),
            "`{spelling}` names this node and must resolve to the one audience it publishes"
        );
    }
}

/// **A deployment that declared no identity gets NO audience, rather than a made-up one.**
///
/// The empty string is not an identity. An audience derived from one would be a resource indicator
/// no client could ever be told to ask for, so the honest answer is that this deployment has none —
/// and the composition that needs one refuses rather than serving a door nothing can be checked
/// against.
#[test]
fn a_node_that_declared_no_identity_publishes_no_audience() {
    let chain = PlaneChain::over(&SURFACE).expect("the declared surface checks");
    assert_eq!(chain.audience(""), None);
    assert_eq!(chain.audience("   "), None);
}

/// **A surface that mounts nothing publishes no audience either.**
///
/// A protocol whose bindings declare no mount has no canonical resource to name, and inventing one
/// out of the binding's name would be the root deciding a protocol's address.
#[test]
fn a_surface_with_no_mount_publishes_no_audience() {
    const UNMOUNTED: WireSurface = WireSurface {
        bindings: &[BindingDecl {
            name: "doc",
            transport: T_HTTP,
            mounts: &[],
        }],
        operations: &[Operation {
            op: "two",
            dispatch: D_TWO,
            answering: Answering::Unary,
            request_media: "application/json",
            response_media: "application/json",
        }],
    };
    let chain = PlaneChain::over(&UNMOUNTED).expect("the surface checks");
    assert_eq!(chain.audience("https://gateway.example.com"), None);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE NODE'S OWN PARTS, HANDED TO ONE WALK
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **Two walks on one chain are two units, and the node's counters are shared between them.**
///
/// The keys are what the cell reads, because they are the visible half of the thing that matters:
/// the gauge and the canary are the NODE's and are held once, so a composition that made a fresh
/// set per request would be counting each unit against an empty node. A second key equal to the
/// first would say exactly that.
#[test]
fn each_walk_is_its_own_unit_on_the_node_s_own_counters() {
    let chain = PlaneChain::over(&SURFACE).expect("the declared surface checks");
    let kernel = crate::root::kernel::new_kernel();
    let first = chain.run(&kernel, |ctx, _run| ctx.key);
    let second = chain.run(&kernel, |ctx, _run| ctx.key);
    assert_ne!(
        first, second,
        "two arrivals are two units and must not share one unit key"
    );
}

/// **A unit walked on a data listener is not an administrative one.**
///
/// Both flags are answered with what is true for a data plane rather than derived, because the
/// wrong answer here is silent: a node that ran these as kernel verbs would be admitting ordinary
/// traffic through the operator's door.
#[test]
fn a_data_plane_unit_is_not_an_administrative_one() {
    let chain = PlaneChain::over(&SURFACE).expect("the declared surface checks");
    let kernel = crate::root::kernel::new_kernel();
    let (administrative, verb_only, origin) = chain.run(&kernel, |ctx, _run| {
        (ctx.admin_listener, ctx.kernel_verb_only, ctx.origin)
    });
    assert!(
        !administrative,
        "a data listener is not the administrative one"
    );
    assert!(
        !verb_only,
        "a unit of an ordinary plane is not a kernel verb"
    );
    assert_eq!(origin, busbar_caps::OriginKind::Client);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE DEPLOYMENT'S OWN DOOR
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **A configured chain naming only the built-in signed-key arm resolves, with the arm ON.**
///
/// The arm is not a module and cannot be boxed, so the only thing that keeps the door shut for a
/// `chain: [keys]` deployment is this flag. A chain that resolved with it off would be an open front
/// door on a node whose operator wrote down an authentication requirement.
#[test]
fn a_chain_naming_the_signed_key_arm_resolves_with_the_arm_on() {
    let chain = data_chain(&[ChainPosition {
        provider: "primary",
        module: busbar_unit_auth::chain::KEYS_MODULE,
    }])
    .expect("the built-in arm is resolvable at every composition");
    assert!(
        chain.keys_in_chain(),
        "the configuration named the signed-key arm and the resolved chain must run it"
    );
    assert!(
        !chain.is_open(),
        "a chain naming the arm is not the open front door"
    );
}

/// **A configured chain that names NOTHING is the open front door, and says so.**
///
/// The deployment that wrote `chain: []` asked for anonymous admission and gets it. It is a
/// posture and not a missing source, which is why it resolves rather than refusing.
#[test]
fn an_empty_configured_chain_is_the_open_door() {
    let chain = data_chain(&[]).expect("a configuration that names no position resolves");
    assert!(
        chain.is_open(),
        "a deployment that named no authentication position configured the open front door"
    );
}

/// **A configured position this composition cannot resolve REFUSES, naming the provider.**
///
/// The whole value of the refusal. A plugin-backed identity provider is resolved by the engine's
/// own loader and is not reachable here; a chain that quietly dropped it would serve the deployment
/// a door with one fewer lock than its operator wrote down, and every request would look admitted
/// rather than unchecked.
#[test]
fn a_position_this_composition_cannot_resolve_refuses_by_name() {
    let refusal = data_chain(&[
        ChainPosition {
            provider: "primary",
            module: busbar_unit_auth::chain::KEYS_MODULE,
        },
        ChainPosition {
            provider: "corporate-idp",
            module: "oidc",
        },
    ])
    .expect_err("a provider with no module at this composition must refuse");
    let said = format!("{refusal}");
    assert!(
        said.contains("corporate-idp") && said.contains("oidc"),
        "the refusal must name the provider AND the module it wanted, so an operator reads which \
         line of configuration this node cannot honour: got `{said}`"
    );
}

/// **The refusal is about the position, not about how many there are.**
///
/// A single unresolvable position refuses on its own: there is no arm where a chain with one good
/// module carries an unresolved one alongside it.
#[test]
fn one_unresolvable_position_refuses_on_its_own() {
    assert!(data_chain(&[ChainPosition {
        provider: "corporate-idp",
        module: "oidc",
    }])
    .is_err());
}
