//! The one base trait every plugin implements, and the closed set of kinds.
//!
//! The core-to-plugin section of the design states the shape: one base trait, one registry type,
//! and registration as the only way in. Every plugin is passive — the kernel registers it, calls
//! it, and consumes what it returns. Nothing here lets a plugin call back into the kernel.

use core::fmt;

pub(crate) mod sealed {
    /// The private supertrait that closes the kind marker set.
    pub trait KindSeal {}

    /// The private supertrait that closes [`KernelSeal`](super::KernelSeal) (#65).
    ///
    /// This module is `pub(crate)`, so no crate outside this one can NAME this trait, and a trait
    /// that cannot be named cannot be implemented. That makes `KernelSeal` implementable by
    /// exactly the types this crate implements it for — the capability tokens in
    /// [`crate::caps::token`] — and turns "only the kernel builds a kernel-built view" from a
    /// source scan into a thing the type checker enforces.
    pub trait KernelSealed {}
}

/// The closed set of plugin kinds — SEVEN of them: plane, transport, auth, store, secret, hook,
/// export.
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
    /// Turns an arriving credential into facts about a principal, and decorates an outbound one
    /// with an upstream's own scheme. ONE kind, two operations: direction is a property of the
    /// leg — `(transport, auth, direction)` — never a kind of its own.
    Auth,
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

    // The PURE kinds — plane, hook, and the auth plugins that do no I/O of their own — are the ones
    // the core-to-plugin section scopes its source denylist to; the input/output kinds (store,
    // secret, export, and the network-backed auth plugins) own their input and output by definition
    // and are bounded by their signature, a deadline and an access journal entry instead. That
    // partition was also spelled here as a predicate no caller in the workspace ever asked, and the
    // rule it stated is enforced by `source-denylist:*` in the construction gate, over the crates
    // rather than over this enum. One statement of it, in the place that acts on it.
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Plane => "plane",
            Self::Transport => "transport",
            Self::Auth => "auth",
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
        /// Marker for the auth kind, inbound and outbound alike.
        AuthKind => Auth);
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
pub use crate::transport::AbiVersion;

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
/// **This trait is SEALED** (#65). It is implementable only by the capability tokens in
/// [`crate::caps::token`], because its supertrait [`sealed::KernelSealed`] lives in a `pub(crate)`
/// module: a crate outside this one cannot name that trait, and what cannot be named cannot be
/// implemented. The earlier text here claimed sealing was impossible because "the capability crate
/// sits ABOVE this one" — that was true when the tokens lived in a separate crate. They do not:
/// `caps` is a MODULE of this crate, so the ordinary private-supertrait pattern reaches them and
/// locks everyone else out. The claim below is now the type system's, not a scan's.
///
/// So the populations collapse to one rule:
///
/// - No crate outside this one can implement this trait AT ALL — in-tree or out-of-tree, test code
///   or production. The compiler refuses it; see the `compile_fail` fixture below. A fixture that
///   needs a seal mints a real token instead, which routes it through
///   [`KernelSeal::acquire_for_kernel`](crate::caps::KernelSeal::acquire_for_kernel) — the one
///   audited symbol CI's `seal-witness` scan watches.
/// - The `kernel-seal-impls` source scan in the construction gate still runs, but it is now a
///   belt-and-braces check behind a compiler guarantee rather than the only thing standing there.
///
/// The trait is also absent from this crate's ROOT surface: it is reachable only as
/// `busbar_contract::plugin::KernelSeal`, so it is not in the list of names a plugin author reads
/// as the ABI.
///
/// The root spelling does not resolve:
///
/// ```compile_fail,E0432
/// use busbar_contract::KernelSeal;
/// ```
///
/// An outside crate cannot implement it. The supertrait that closes the set lives in a
/// crate-private module, so a foreign type cannot satisfy the bound — the COMPILER refuses the
/// forgery, rather than a source scan noticing it afterwards (#65):
///
/// ```compile_fail,E0277
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
pub trait KernelSeal: sealed::KernelSealed {
    /// Which kernel-side crate the seal came from, for the journal's access entry.
    fn seal_origin(&self) -> &'static str;
}

/// The one seal a TEST harness may present — behind the `test-seal` feature, off in every real
/// build.
///
/// This exists because sealing [`KernelSeal`] (#65) closed a door that in-tree test harnesses were
/// walking through. Most of them now mint a real capability token instead, but a PLANE crate may
/// not name [`crate::caps`] at all (ARCHITECTURE section 1.2; each plane asserts it from the inside
/// in its own `purity` test), so a plane's harness has no token to mint and no legal way to build
/// the kernel-side values its fixtures need. `qa/construction.toml`'s `kernel-seal-impls` rule
/// named this exact gap and the exact remedy — *"their test seals cannot move onto a token until
/// the contract offers a seal a plane is allowed to name"*. This is that seal.
///
/// What it does NOT do is re-open the forgery:
///
/// - It is `#[cfg(feature = "test-seal")]`, and **no non-dev dependency edge in this workspace
///   turns that feature on**. In a release build this type does not exist, so nothing shipped can
///   name it.
/// - A crate must opt in LOUDLY, in its own `[dev-dependencies]`, under a feature whose name says
///   what it is. That is an edit a reviewer sees, unlike the old `struct FakeSeal; impl KernelSeal
///   for FakeSeal` which any file could write silently.
/// - The trait stays sealed. This is one more in-crate implementor, not a re-opened trait: an
///   outside crate still cannot implement [`KernelSeal`], with or without the feature.
///
/// The TYPE is declared here so a plane can NAME it (`busbar_contract::plugin::TestKernelSeal`);
/// its two `impl` blocks live in [`crate::caps::token`] with every other implementor of this
/// trait, which is both where `qa/construction.toml`'s `kernel-seal-impls` rule requires them and
/// the point of that rule — one directory holds every type that can present a seal.
#[cfg(feature = "test-seal")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestKernelSeal;
