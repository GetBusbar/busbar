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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum Kind {
    /// Says what bytes mean. Pure, no input or output of its own.
    Plane,
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

    /// Whether the kind is one of the pure kinds the source denylist is scoped to.
    ///
    /// The core-to-plugin section scopes the denylist to planes, hooks, pure static auth schemes
    /// and egress-auth schemes. The input/output kinds — store, secret, export and the
    /// network-backed auth plugins — own their input and output by definition and are bounded by
    /// their signature, a deadline and an access journal entry instead.
    #[must_use]
    pub const fn is_pure_kind(self) -> bool {
        matches!(self, Self::Plane | Self::Hook | Self::EgressAuth)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Plane => "plane",
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

    macro_rules! marker {
        ($(#[$meta:meta])* $name:ident => $kind:ident) => {
            $(#[$meta])*
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct $name;
            impl KindSeal for $name {}
            impl KindMarker for $name {
                const KIND: Kind = Kind::$kind;
            }
        };
    }

    marker!(
        /// Marker for the plane kind.
        PlaneKind => Plane);
    marker!(
        /// Marker for the transport kind.
        TransportKind => Transport);
    marker!(
        /// Marker for the ingress auth kind.
        AuthKind => Auth);
    marker!(
        /// Marker for the egress auth-scheme kind.
        EgressAuthKind => EgressAuth);
    marker!(
        /// Marker for the store kind.
        StoreKind => Store);
    marker!(
        /// Marker for the secret kind.
        SecretKind => Secret);
    marker!(
        /// Marker for the hook kind.
        HookKind => Hook);
    marker!(
        /// Marker for the export kind.
        ExportKind => Export);
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
