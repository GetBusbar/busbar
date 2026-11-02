//! The one base trait every plugin implements, and the closed set of kinds.

use core::fmt;

pub(crate) mod sealed {
    /// The private supertrait that closes the kind marker set.
    pub trait KindSeal {}

    /// The private supertrait that closes [`KernelSeal`](super::KernelSeal) (#65).

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

    /// THE KIND → VERB LIST: the config root key each kind is configured under. The one place a

    #[must_use]
    pub const fn verb(self) -> Verb {
        match self {
            Self::Store => Verb::Root("store"),
            Self::Secret => Verb::Root("secrets"),
            Self::Auth => Verb::Root("identity-providers"),
            Self::Hook => Verb::Root("hooks"),
            Self::Export => Verb::Root("export"),
            Self::Transport => Verb::Root("providers"),
            Self::Plane => Verb::Declared,
        }
    }

    /// The root key of a kind whose verb is a root key, else `None` (a plane: see [`Kind::verb`]).
    #[must_use]
    pub const fn root_key(self) -> Option<&'static str> {
        match self.verb() {
            Verb::Root(key) => Some(key),
            Verb::Declared => None,
        }
    }

    /// The root key of a non-plane kind — how kernel and plugin code name it.

    #[must_use]
    pub const fn root(self) -> &'static str {
        match self.root_key() {
            Some(key) => key,
            None => panic!("a plane's verbs are declared by the plane, never named by the kernel"),
        }
    }

    /// Every kind, in declaration order.
    pub const ALL: [Kind; 7] = [
        Self::Plane,
        Self::Transport,
        Self::Auth,
        Self::Store,
        Self::Secret,
        Self::Hook,
        Self::Export,
    ];
}

/// Where a kind is configured: one root key the kernel knows, or the verbs each plane plugin
/// declares for itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    /// One root key, owned by the kind — never by any one plugin of it.
    Root(&'static str),
    /// Declared by each plane plugin in its declaration; the kernel names none.
    Declared,
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
pub use crate::transport::AbiVersion;

/// The base trait every plugin implements.

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
/// This trait is sealed to the capability tokens in [`crate::caps::token`]. Its supertrait [`sealed::KernelSealed`] is in a private module, so external crates cannot name or implement it. The capability tokens live in this crate's `caps` module and can implement that private supertrait.
///
///
///
///
///
///
///
/// So the populations collapse to one rule:
///
/// - No crate outside this one can implement this trait AT ALL — in-tree or out-of-tree, test code
///   or production. The compiler refuses it; see the `compile_fail` fixture below. A fixture that
///   needs a seal mints a real token instead, and a real token needs the kernel's seal, which
///   reaches only the kernel ([`KernelSeal::deliver`](crate::caps::KernelSeal::deliver), #65);
///   a test mints with the test-only `acquire_for_kernel`, which CI's `seal-witness` scan watches.
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
/// Plane crates cannot name
/// [`crate::caps`] under their purity
/// boundary. The dev-only seal
/// lets their test harnesses
/// build kernel-side fixture
/// views without implementing
/// or reopening [`KernelSeal`].
///
/// What it does NOT do is re-open the forgery:
///
/// - It is `#[cfg(any(test, feature = "test-seal"))]`: this crate's own unit tests (whose
///   `Secret<T>` cell presents it) and the dev-only feature, and **no non-dev dependency edge in
///   this workspace turns that feature on**. In a release build this type does not exist, so
///   nothing shipped can name it.
/// - A crate must opt in LOUDLY, in its own `[dev-dependencies]`, under a feature whose name says
///   what it is. This keeps the dev-only construction opt-in explicit.
/// - The trait stays sealed. This is one more in-crate implementor, not a re-opened trait: an
///   outside crate still cannot implement [`KernelSeal`], with or without the feature.
///
///
/// The TYPE is declared here so a plane can NAME it (`busbar_contract::plugin::TestKernelSeal`);
/// its two `impl` blocks live in [`crate::caps::token`] with every other implementor of this
/// trait, which is both where `qa/construction.toml`'s `kernel-seal-impls` rule requires them and
/// the point of that rule — one directory holds every type that can present a seal.
#[cfg(any(test, feature = "test-seal"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestKernelSeal;

/// Is `v` a well-formed semver core (`MAJOR.MINOR.PATCH`, each a decimal integer, with an optional

#[must_use]
pub fn valid_semver(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
#[path = "tests/kind_verb_tests.rs"]
mod kind_verb_tests;
