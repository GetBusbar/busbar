//! The open vocabulary: the keys a plugin declares and the kernel dispatches on.
//!
//! The open-vocabulary section of the design draws the line these types sit on. The kernel has no
//! closed list a plugin could need to extend; everything a plugin varies is a key into a registry
//! or into config. Only structure is closed. So each identifier below is a name, not a variant,
//! and the kernel never compares one against a literal of its own.
//!
//! Every identifier is a borrowed static string. That is deliberate: the declarations that carry
//! them are associated constants on the meta traits, and a constant cannot own a heap allocation.
//! A dynamically loaded plugin's keys come in through its adapter, which leaks the strings once at
//! load and hands over static names.

use core::fmt;

macro_rules! declare_id {
    ($(#[$meta:meta])* $name:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        pub struct $name(&'static str);

        impl $name {
            #[doc = concat!("Name ", $what, ".")]
            #[must_use]
            pub const fn new(key: &'static str) -> Self {
                Self(key)
            }

            /// The declared name.
            #[must_use]
            pub const fn as_str(&self) -> &'static str {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }
    };
}

declare_id!(
    /// One class of operation a plane declares, priced through the lanes it permits.
    OpClassId,
    "an operation class"
);
declare_id!(
    /// One read-only introspection verb a plane declares.
    AdminVerbId,
    "a plane admin verb"
);
declare_id!(
    /// One claim a plane declares, named so policy can be written against it.
    ///
    /// The scope step's lookup key is the pair `(claim, operation class)`, so the claim needs a
    /// name of its own: without one a plane's operations can be declared but never scoped, because
    /// there is no way to say which of its claims a policy entry is about.
    ClaimKey,
    "a declared claim"
);
declare_id!(
    /// One class of metered quantity.
    ///
    /// A meter class is the unit of both pricing and capping: the cap-dimension shape below is
    /// closed over an open key, so any declared class is cappable without a new variant.
    MeterClassId,
    "a meter class"
);
declare_id!(
    /// One record schema a plane declares for its kernel-held durable records.
    RecordSchemaId,
    "a record schema"
);
declare_id!(
    /// A transport's registry identity.
    ///
    /// This is a registry name and never key material; the opaque key handle is the only thing
    /// that carries a key.
    TransportId,
    "a transport"
);
declare_id!(
    /// The priced axis: a config-declared name per plane and upstream.
    ///
    /// The type index calls the lane the rate card's first key. It is carried on a verified
    /// destination, located in the request by the admit facts, located in the response by the
    /// plane's own facts, and all three readings are compared through the lane-alias map.
    LaneId,
    "a lane"
);
declare_id!(
    /// One credential scheme key.
    SchemeKey,
    "an auth scheme"
);
declare_id!(
    /// One alternative a plane may narrow a claim's scheme to.
    SchemeAlt,
    "a declared scheme alternative"
);

/// A stream inside one connection.
///
/// One-shot transports use a single stream; multiplexed transports number theirs. The kernel keys
/// the open-unit slot on the session, the stream and the direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct StreamId(pub u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream {}", self.0)
    }
}

/// A session's identity, minted by the kernel at unit zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct SessionId(pub u64);

/// A unit's node-local identity, minted by the kernel when it builds the unit.
///
/// This is the key the in-flight table, the journal and every capability type name a unit by. It
/// lives here rather than in the capability crate because a unit is the contract's object: the
/// capability types are keyed on it, they do not own it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct UnitKey(u64);

impl UnitKey {
    /// Name a unit.
    #[must_use]
    pub const fn new(key: u64) -> Self {
        Self(key)
    }

    /// The key as the journal writes it.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for UnitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unit {}", self.0)
    }
}

/// An upstream's index within one session.
///
/// Returned by the session plane when it opens an upstream. The crate-graph section bounds the
/// count per session; an index outside that range never reaches a verified destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct UpstreamIdx(pub u8);

/// Who a unit is for.
///
/// The auth kind resolves this; a plane never sees a credential and never mints a principal. The
/// anonymous principal is the kernel's own and has no bucket.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Name a principal.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identity as the audit row prints it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The value found under a correlation's declared fact key.
///
/// Two shapes, because two shapes is what arrives. A protocol whose request identifier is a whole
/// number carries it as one; a protocol whose identifier is a string carries the string, allocated
/// in the unit's arena so it lives as long as the unit that correlates on it.
///
/// The string arm exists because the alternative is a digest, and a digest of a string into sixty
/// four bits is a collision waiting for two identifiers of one principal on one session — which is
/// the pair a correlation is precisely meant to tell apart. Correlation decides which hold a
/// provider frame accrues into, so a collision there moves money between two units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum CorrelationValue<'u> {
    /// A whole number identifier, used as itself.
    Num(u64),
    /// A string identifier, borrowed from the unit's arena.
    Str(&'u str),
}

/// How a plane ties a response frame back to the request that asked for it.
///
/// A correlation reference is a fact key plus the value found under it. The plane declares the key;
/// the kernel never invents one and never parses for one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct CorrelationRef<'u> {
    /// The declared fact key the correlation is carried under.
    pub fact_key: &'static str,
    /// The value found under that key.
    pub value: CorrelationValue<'u>,
}

/// Which side of a meter class's bytes a quantity comes from.
///
/// The plugin-kinds table calls this the class family, and it says the rate card may price a class
/// but may never re-family it. The input-side families partition the same bytes; the kernel-side
/// families sit outside that partition and outside the response estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ClassDirection {
    /// Sized from the ingress-derived estimate.
    Input,
    /// Sized from the response ceiling.
    Response,
    /// Ingress bytes served from an upstream cache.
    CacheRead,
    /// Ingress bytes written to an upstream cache.
    CacheWrite,
    /// Sized by the kernel's own rule, outside the ingress partition.
    Kernel,
}

/// A plane's declaration of one meter class.
///
/// The divisor converts bytes to the class's own quantity and has a pinned default here so that
/// class caps work with no rate card at all; a card may override it but may not re-family the
/// class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct MeterClassDecl {
    /// The class key.
    pub key: MeterClassId,
    /// The family name this class rolls up into.
    pub family: &'static str,
    /// Which side of the bytes the class is sized from.
    pub direction: ClassDirection,
    /// Bytes per unit of the class's own quantity.
    pub default_divisor: u32,
}

/// The closed shape of a cappable dimension over an open key.
///
/// The open-vocabulary section is explicit that this is a closed *shape*, not a closed list of
/// quantities: any declared meter class is cappable by key, so token, byte and message caps are
/// instances rather than variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum CapDimension {
    /// Money, in nano-units.
    NanoUnits,
    /// The admission counter.
    Requests,
    /// The instantaneous gauge.
    Concurrent,
    /// Any declared meter class, by key.
    Class(MeterClassId),
}

/// How wide a bucket's cap reaches.
///
/// A scope-limited bucket draws only when its scope equals the effective pool name, and a draw on
/// a scope the unit did not route through is released at the routing step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum BucketScope {
    /// Every pool.
    All,
    /// One named pool, validated against the configured pools.
    Pool(&'static str),
}

/// One bucket in a principal's chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct BucketRef {
    /// The bucket's identity as the refusal text prints it.
    pub id: &'static str,
    /// How wide the bucket's cap reaches.
    pub scope: BucketScope,
    /// Whether the bucket caps anything at all; an uncapped bucket is an attribution bucket.
    pub capped: bool,
}

/// The chain of buckets one principal draws against, all or nothing.
///
/// One tier multiplier governs the whole chain; a chain whose buckets disagree on the tier is a
/// mismatch, not an average.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BucketChain {
    /// The buckets, in pool-filtered chain order.
    pub buckets: crate::bounded::BoundedVec<BucketRef, { crate::bounded::MAX_KEYS }>,
    /// The chain's tier multiplier, in basis points.
    pub tier_bp: u32,
}

/// One class's share of a unit's estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ClassEstimate {
    /// The class being estimated.
    pub class: MeterClassId,
    /// The estimated quantity, in the class's own units.
    pub quantity: u64,
}

/// What the admission step sizes a hold against.
///
/// The estimate is per class. The whole ingress-derived figure is assigned to the single most
/// expensive class of the input partition and zero to the others, so the sum across classes here
/// equals the maximum the hold has to cover, and the metering step settles to the split the
/// upstream actually reported.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Estimate {
    /// One line per class the unit may consume.
    pub per_class: crate::bounded::BoundedVec<ClassEstimate, { crate::bounded::MAX_USAGE_LINES }>,
}

/// How many distinct keys one image may ever intern.
///
/// The freeze below is what a composition root does. This is what holds where there is no
/// composition root to do it: a test binary, a bench, a fuzz target, or a dynamically loaded plugin
/// linked against its own copy of this crate, which gets its own statics and therefore its own
/// vocabulary. In each of those the freeze never happens, and this ceiling is the whole bound.
///
/// Sized for configuration, not for traffic: it is lanes plus pools plus models plus hosts plus
/// dialects plus agents plus tool servers plus plugin keys, for a deployment far larger than any
/// that has been configured. A node that reaches it has a defect, not a big configuration.
pub const MAX_VOCABULARY: usize = 4096;

/// The image's one vocabulary, and whether it is still open.
///
/// A `static` rather than state on the registration value because the LEAKED STRINGS are the
/// resource and the resource is process-wide. Ownership of a registration value bounds nothing:
/// the value is constructible by anyone, so a bound that lives inside one instance is a bound per
/// instance, which is no bound at all against a caller that makes a fresh instance per request.
static VOCABULARY: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<&'static str>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
static FROZEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The one place a configured string becomes a declared key.
///
/// Every identifier on this surface is a borrowed static string, because the declarations that
/// carry them are associated constants and a constant cannot own a heap allocation. But lanes,
/// hosts, dialects and models are CONFIGURED: they are read at boot, and a value read at boot is
/// not static on its own. Something has to bridge those two facts, and until now nothing named
/// what — so four planes coped with a const table the composition root was expected to seal
/// somehow, and one transport leaked a fresh string on every dial, which is a leak per request.
///
/// This is that bridge, and it is the composition root's. The root builds one of these at boot,
/// interns every config-derived open-vocabulary key through it, and hands the resulting static
/// names to the registrations that declare them. The set is finite because configuration is finite;
/// it is leaked ONCE because interning is idempotent; and its size is a fixed term of the node's
/// resident memory rather than a term that grows with traffic. Nothing outside registration may
/// intern: a key minted per unit would be exactly the leak this replaces.
///
/// ## How "nothing outside registration" is held
///
/// Not by who owns this value. This value is constructible by anyone, and it has to be: a plane, a
/// transport and a unit crate all build one in their own tests, and the contract is the plugin-
/// visible ABI, so any seal on the constructor is a seal a plugin can name. What holds instead is
/// that the resource being spent — leaked `&'static str` — is process-wide, so the bound is
/// process-wide too. Every registration in one image reads and writes ONE vocabulary. The
/// composition root fills it at boot and calls [`freeze`](Self::freeze); after that, [`key`] is a
/// LOOKUP: a name the root registered still resolves, from anywhere, and a name it did not is
/// refused. A plane that holds a registration of its own and asks for a name it took off a request
/// gets `None`, having allocated nothing, no matter how many registrations it makes.
///
/// The refusal is returned as a value and never raised as a panic, because the name that reaches it
/// is client-supplied: a panic there is a way for a request to stop the node, which is a worse
/// failure than the leak being closed. And [`MAX_VOCABULARY`] bounds an image whose freeze never
/// happens at all, which is every image that has no composition root in it.
///
/// [`key`]: Self::key
#[derive(Debug, Default)]
pub struct Registration {
    interned: std::collections::HashSet<&'static str>,
}

impl Registration {
    /// A registration with nothing interned yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The static name for one configured key: interned if the vocabulary is open, resolved if it
    /// is already there, and refused otherwise.
    ///
    /// Idempotent: asking twice yields the same name and leaks once. `None` says the key is not in
    /// this image's vocabulary and cannot be added to it — because boot is over, or because the
    /// ceiling is reached — which is a refusal to route on that name, not an error to recover from.
    pub fn key(&mut self, value: &str) -> Option<&'static str> {
        let mut vocabulary = VOCABULARY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let found = if let Some(existing) = vocabulary.get(value) {
            *existing
        } else if FROZEN.load(std::sync::atomic::Ordering::Acquire)
            || vocabulary.len() >= MAX_VOCABULARY
        {
            return None;
        } else {
            let leaked: &'static str = Box::leak(value.to_owned().into_boxed_str());
            vocabulary.insert(leaked);
            leaked
        };
        drop(vocabulary);
        self.interned.insert(found);
        Some(found)
    }

    /// The [`LaneId`] for one configured lane name.
    ///
    /// The priced axis is declared as a borrowed static name and a configured lane's name is read
    /// at boot, so something has to bridge the two — and the bridge is this one, not a second id
    /// type that owns its string. An owned lane id would double the type every rate-card key, every
    /// verified destination and every locator comparison is written in, for one configured value;
    /// interning keeps the axis one `Copy` name and pays a fixed registration-time allocation for
    /// it. Refuses for the same reasons [`key`](Self::key) does: a lane nobody registered is not a
    /// lane this node routes to.
    pub fn lane(&mut self, name: &str) -> Option<LaneId> {
        self.key(name).map(LaneId::new)
    }

    /// Close the image's vocabulary. The composition root's last registration-time act.
    ///
    /// Idempotent, and one-way: there is no thaw, because a vocabulary that can be reopened is a
    /// vocabulary a request path can reopen. Calling it before the root has finished registering
    /// costs the node its own configured names and fails the boot loudly — which is the right shape
    /// for a first-party ordering mistake, and is not something a request can cause.
    pub fn freeze() {
        FROZEN.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether the vocabulary has been closed.
    #[must_use]
    pub fn is_frozen() -> bool {
        FROZEN.load(std::sync::atomic::Ordering::Acquire)
    }

    /// How many distinct keys this IMAGE has interned.
    ///
    /// The fixed resident-memory term is counted from here, so it is readable rather than inferred,
    /// and it is the process's count rather than one registration's because the leak is the
    /// process's.
    #[must_use]
    pub fn interned() -> usize {
        VOCABULARY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// How many distinct keys this registration has resolved.
    #[must_use]
    pub fn len(&self) -> usize {
        self.interned.len()
    }

    /// Whether this registration has resolved nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.interned.is_empty()
    }
}
