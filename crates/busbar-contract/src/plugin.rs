//! The one base trait every plugin implements, and the closed set of kinds.
//!
//! The core-to-plugin section of the design states the shape: one base trait, one registry type,
//! and registration as the only way in. Every plugin is passive — the kernel registers it, calls
//! it, and consumes what it returns. Nothing here lets a plugin call back into the kernel.

use core::fmt;

mod sealed {
    /// The private supertrait that closes the kind marker set.
    pub trait KindSeal {}
}

/// The closed set of plugin kinds.
///
/// This is structure, not vocabulary, so it is closed: the open-vocabulary section of the design
/// allows a plugin to invent claims, classes and schemes, but never a new kind of plugin. A new
/// kind is a kernel change and is meant to look like one.
///
/// The set is the kind table of `docs/design/PLUGIN-TREE.md`, which is normative for it, and the
/// order below is that table's. Two of the variants name kinds whose crates have not landed yet,
/// and they are here rather than owed for one reason: `Plugin::kind()` returns a member of THIS
/// set, so a kind the set cannot name is a kind whose crates must declare themselves something
/// they are not — and the isolation gate would then check them against the wrong skeleton, which
/// is the one guarantee those two kinds most need.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum Kind {
    /// Says what bytes mean. Pure, no input or output of its own.
    Plane,
    /// A plane's WIRE DIALECT: translates bytes to and from its own plane's IR, and nothing else.
    ///
    /// Pure, and the narrowest kind in the tree — a dialect declares its plane, its claims and its
    /// locations, and the only cross-crate edge the whole plugin tree carves out by hand is this
    /// kind's edge to the plane whose IR it names. A dialect registers INTO its plane by claim; the
    /// plane never names a dialect back.
    Dialect,
    /// A CONTROL SURFACE: an unmetered served surface that answers on the control path.
    ///
    /// The metering is the whole of the split from [`Kind::Plane`]. A control surface declares its
    /// routes as data, owns its own request and response bodies, and is verified, admitted, audited
    /// and answered — it reads node state through contract traits, changes it only through the
    /// verbs unit, and mints credentials only through the auth unit's signer. It names no money
    /// vocabulary, reaches no upstream, appears in no plane's step list and calls no plane, holds
    /// no key material and no process-global state.
    Control,
    /// Moves bytes. In-tree only, inside the trusted computing base.
    Transport,
    /// Turns an arriving credential into facts about a principal.
    Auth,
    /// Decorates an outbound request with an upstream's own scheme.
    EgressAuth,
    /// The durable store behind the journal.
    Store,
    /// Resolves, signs, seals and unseals key material.
    Secret,
    /// Observes or gates a unit at one of the four seats.
    Hook,
    /// Ships journal entries, content facts or segments off the node.
    Export,
}

impl Kind {
    /// The kind a marker type stands for.
    #[must_use]
    pub const fn of<K: KindMarker>() -> Self {
        K::KIND
    }

    // The PURE kinds — plane, hook, and the pure static and egress-auth schemes — are the ones the
    // core-to-plugin section scopes its source denylist to; the input/output kinds (store, secret,
    // export, and the network-backed auth plugins) own their input and output by definition and are
    // bounded by their signature, a deadline and an access journal entry instead. That partition was
    // also spelled here as a predicate no caller in the workspace ever asked, and the rule it stated
    // is enforced by `source-denylist:*` in the construction gate, over the crates rather than over
    // this enum. One statement of it, in the place that acts on it.
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Plane => "plane",
            Self::Dialect => "dialect",
            Self::Control => "control",
            Self::Transport => "transport",
            Self::Auth => "auth",
            Self::EgressAuth => "egress-auth",
            Self::Store => "store",
            Self::Secret => "secret",
            Self::Hook => "hook",
            Self::Export => "export",
        };
        f.write_str(s)
    }
}

/// A compile-time stand-in for one kind.
///
/// The trait is sealed by a private supertrait, so the marker set cannot be extended outside this
/// crate. That is the whole of the sealed-kind pattern: a kind trait below is implementable by any
/// plugin, but the *set* of kinds is not.
pub trait KindMarker: sealed::KindSeal {
    /// Which kind this marker stands for.
    const KIND: Kind;
}

/// The compile-time markers, one per kind.
pub mod markers {
    use super::{sealed::KindSeal, Kind, KindMarker};

    // ONE INVOCATION OVER THE WHOLE SET, not one per kind. The markers are the same three lines of
    // generated code each, so writing them as a list rather than as N calls means adding a kind
    // costs the line that NAMES it and nothing else — which is the shape a closed set that is meant
    // to be extended by an owner ruling should have, and is what let the dialect and control
    // markers land inside the contract pair's LOC ceiling without it moving.
    macro_rules! marker {
        ($($(#[$meta:meta])* $name:ident => $kind:ident;)*) => {$(
            $(#[$meta])*
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct $name;
            impl KindSeal for $name {}
            impl KindMarker for $name {
                const KIND: Kind = Kind::$kind;
            }
        )*};
    }

    marker! {
        /// Marker for the plane kind.
        PlaneKind => Plane;
        /// Marker for the dialect kind.
        DialectKind => Dialect;
        /// Marker for the control-surface kind.
        ControlKind => Control;
        /// Marker for the transport kind.
        TransportKind => Transport;
        /// Marker for the ingress auth kind.
        AuthKind => Auth;
        /// Marker for the egress auth-scheme kind.
        EgressAuthKind => EgressAuth;
        /// Marker for the store kind.
        StoreKind => Store;
        /// Marker for the secret kind.
        SecretKind => Secret;
        /// Marker for the hook kind.
        HookKind => Hook;
        /// Marker for the export kind.
        ExportKind => Export;
    }
}

/// The native plugin interface generation a plugin was built against.
///
/// Declared one crate down, beside the transport kind's own generation, so that the two constants
/// a registry compares are the same type rather than two newtypes that happen to wrap the same
/// number and compare equal to nothing.
pub use busbar_contract_transport::AbiVersion;

/// The store kind's native interface generation.
///
/// The other-kinds section pins it, and it also fixes the compatibility rule: an older store loads
/// through an in-tree adapter rather than being refused, so a configuration written for the
/// previous release boots unchanged.
pub const STORE_ABI: AbiVersion = AbiVersion(5);

/// The dialect kind's native interface generation.
///
/// Generation 1, because the kind is new and no dialect has ever been loaded against an earlier
/// one: there is nothing for an adapter to adapt, and starting anywhere else would imply a history
/// this kind does not have.
pub const DIALECT_ABI: AbiVersion = AbiVersion(1);

/// The control kind's native interface generation.
///
/// Generation 1, for the reason [`DIALECT_ABI`] is. A control surface is in-tree and served by the
/// node's own mount, so unlike a store there is no out-of-tree population to keep compatible: the
/// floor exists so the registry has the same thing to compare for this kind that it compares for
/// every other, not because a second generation is anticipated.
pub const CONTROL_ABI: AbiVersion = AbiVersion(1);

/// The base trait every plugin implements.
///
/// It is deliberately tiny. Everything a plugin *does* is on its kind trait; everything a plugin
/// *is* is here, and all three answers are constants in practice. The trait is object-safe because
/// the registry holds plugins behind a pointer.
pub trait Plugin: Send + Sync + 'static {
    /// The plugin's registry key. This is the open-vocabulary name the kernel dispatches on.
    fn key(&self) -> &'static str;

    /// Which kind this plugin is. It must equal the kind of the trait it implements.
    fn kind(&self) -> Kind;

    /// The interface generation this plugin was built against.
    fn abi(&self) -> AbiVersion;
}

/// The marker a kernel-side crate presents to build a view a plugin may only read.
///
/// The capability section of the design seals the decision types by token in the capability crate,
/// which this crate must not name. The views below — the unit a plane reads, a verified
/// destination, an opaque key handle — are not capabilities, but they are still kernel-built, and a
/// plugin that could fabricate one could fabricate its own evidence. This marker is the seam: the
/// constructors take a reference to one, the capability crate's tokens implement it, and a plugin
/// crate cannot name that crate at all under the manifest allow-list.
///
/// This is honest rather than airtight, and the honesty is worth spelling out because the shape of
/// it decides what may be claimed elsewhere. The trait has to be public: the capability crate sits
/// ABOVE this one and implements it on every token, and there is no Rust construct for "a trait
/// implementable by exactly one other crate" — a private supertrait would lock that crate out too.
///
/// So what stops each population is different, and none of it is the type system:
///
/// - An out-of-tree plugin cannot obtain a token, because the manifest allow-list refuses a plugin
///   crate that names the capability crate at all. It CAN implement this trait on a type of its own.
///   A loaded plugin is signature-verified, operator-installed, trusted code, so that is not a line
///   this system draws.
/// - An in-tree crate is held by a source scan, `kernel-seal-impls` in the construction gate, which
///   forbids implementing this trait anywhere outside the capability crate.
///
/// What this crate does contribute is that the trait is not on its ROOT surface: it is reachable
/// only as `busbar_contract::plugin::KernelSeal`, so it is not in the list of names a plugin author
/// reads as the ABI. That is a smaller claim than "removed", and it is the true one.
///
/// The root spelling does not resolve:
///
/// ```compile_fail,E0432
/// use busbar_contract::KernelSeal;
/// ```
///
/// The module spelling does, and still builds a destination — stated here so this fixture is never
/// misread as a claim that the trait cannot be implemented:
///
/// ```
/// struct FakeSeal;
/// impl busbar_contract::plugin::KernelSeal for FakeSeal {
///     fn seal_origin(&self) -> &'static str {
///         "a crate of my own"
///     }
/// }
/// let forged = busbar_contract::VerifiedDestination::seal(
///     &FakeSeal,
///     busbar_contract::DestinationFacts::KernelVerb { verb: "status" },
///     "http",
///     None,
/// );
/// assert_eq!(forged.transport(), "http");
/// ```
pub trait KernelSeal {
    /// Which kernel-side crate the seal came from, for the journal's access entry.
    fn seal_origin(&self) -> &'static str;
}
