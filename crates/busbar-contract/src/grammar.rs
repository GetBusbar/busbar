//! The closed grammars: claims, selectors, arrival locations and locations.
//!
//! The claims section of the design fixes these three grammars and gives the kernel one job over
//! them — decide, at boot, whether two claims could ever match the same arriving bytes. The
//! decision has to be total: there is no "unknown" answer, because an unknown answer at boot is an
//! ambiguous route at run time. Where the grammar cannot prove two forms disjoint, the answer is
//! that they overlap, and the boot refuses. Conservative in the direction of refusing to start.

use core::fmt;

/// One segment of a path pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum PathSeg {
    /// A literal segment, matched exactly.
    Lit(&'static str),
    /// One segment of any value.
    Var,
    /// Every remaining segment.
    Tail,
}

/// How a transport recognises that arriving bytes are for one particular claim.
///
/// The forms are exactly the ones the transports in the design need, and no more. Adding a form is
/// a kernel change, because [`Selector::overlaps`] has to stay total over the cross-product.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Selector {
    /// One exact path.
    ExactPath(&'static str),
    /// A path prefix, one segment deep.
    PrefixOneLevel(&'static str),
    /// The name offered during the transport-level handshake.
    Sni(&'static str),
    /// The subject of a presented client certificate.
    ClientCertSubject(&'static str),
    /// A segment pattern over the path.
    PathPattern(&'static [PathSeg]),
    /// A header with an exact value.
    HeaderExact(&'static str, &'static str),
    /// A header that is present at all.
    HeaderPresent(&'static str),
    /// A header whose value starts with a prefix.
    HeaderPrefix(&'static str, &'static str),
    /// A path that ends with a literal.
    PathSuffix(&'static str),
    /// A path that contains a literal.
    PathContains(&'static str),
    /// A named stream on a multiplexed transport.
    StreamName(&'static str),
    /// The protocol named during the transport-level handshake.
    Alpn(&'static str),
    /// The local port bytes arrived on.
    Port(u16),
}

/// The name of a selector form, without its value.
///
/// A transport declares the forms it can evaluate; a claim naming a form its transport does not
/// declare is refused at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum SelectorForm {
    /// The exact-path form.
    ExactPath,
    /// The one-level prefix form.
    PrefixOneLevel,
    /// The handshake-name form.
    Sni,
    /// The client-certificate-subject form.
    ClientCertSubject,
    /// The segment-pattern form.
    PathPattern,
    /// The exact-header form.
    HeaderExact,
    /// The header-present form.
    HeaderPresent,
    /// The header-prefix form.
    HeaderPrefix,
    /// The path-suffix form.
    PathSuffix,
    /// The path-contains form.
    PathContains,
    /// The named-stream form.
    StreamName,
    /// The handshake-protocol form.
    Alpn,
    /// The local-port form.
    Port,
}

/// Which part of an arriving request a form reads.
///
/// Two selectors of different families read different parts of the same request, so both can match
/// at once and they overlap conservatively. Two selectors of the same family are compared by the
/// family's own rule, and that is where a genuine disjointness proof is possible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum SelectorFamily {
    /// The request path.
    Path,
    /// A named header.
    Header,
    /// The transport-level handshake.
    Handshake,
    /// A named stream.
    Stream,
    /// The local port.
    Port,
}

impl SelectorForm {
    /// Every form, for the boot cell that walks the cross-product.
    pub const ALL: &'static [SelectorForm] = &[
        SelectorForm::ExactPath,
        SelectorForm::PrefixOneLevel,
        SelectorForm::Sni,
        SelectorForm::ClientCertSubject,
        SelectorForm::PathPattern,
        SelectorForm::HeaderExact,
        SelectorForm::HeaderPresent,
        SelectorForm::HeaderPrefix,
        SelectorForm::PathSuffix,
        SelectorForm::PathContains,
        SelectorForm::StreamName,
        SelectorForm::Alpn,
        SelectorForm::Port,
    ];

    /// Which part of the request the form reads.
    #[must_use]
    pub const fn family(self) -> SelectorFamily {
        match self {
            Self::ExactPath
            | Self::PrefixOneLevel
            | Self::PathPattern
            | Self::PathSuffix
            | Self::PathContains => SelectorFamily::Path,
            Self::HeaderExact | Self::HeaderPresent | Self::HeaderPrefix => SelectorFamily::Header,
            Self::Sni | Self::ClientCertSubject | Self::Alpn => SelectorFamily::Handshake,
            Self::StreamName => SelectorFamily::Stream,
            Self::Port => SelectorFamily::Port,
        }
    }
}

impl fmt::Display for SelectorForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// How a span is hidden once it has been copied into the credential slab.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum MaskKind {
    /// The span is replaced by same-length fill, so offsets downstream do not move.
    SameLengthFill,
    /// Nothing is masked; the value never entered the byte stream.
    Nothing,
    /// Only the signature span is masked.
    SignatureSpan,
    /// A bounded prefix of the handshake frames is masked.
    BoundedPrefix,
}

/// Which bytes a signature covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum SignedOver {
    /// The request target only.
    Url,
    /// The request body only.
    Body,
    /// Both.
    Both,
}

/// Where a credential can be found in arriving bytes.
///
/// These are the only forms an auth scheme's declared locations may use. Each one is resolvable at
/// arrival, before any plane has been chosen, because the arrival gate masks the credential out of
/// the read cursor before a plane ever sees the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ArrivalLocation {
    /// A named header.
    Header(&'static str),
    /// A named query parameter.
    Query(&'static str),
    /// A pointer into the first frame's object notation.
    FirstFrameJsonPointer(&'static str),
    /// The presented client certificate.
    ClientCert,
    /// A signature over the named bytes.
    Signed {
        /// Which bytes the signature covers.
        over: SignedOver,
    },
    /// A bounded prefix of the handshake frames.
    HandshakeFrames {
        /// The most frames the scheme may consume.
        max_frames: u16,
        /// The most bytes the scheme may consume.
        max_bytes: u32,
    },
}

impl ArrivalLocation {
    /// How the arrival gate hides this location's span.
    #[must_use]
    pub const fn mask(&self) -> MaskKind {
        match self {
            Self::Header(_) | Self::Query(_) | Self::FirstFrameJsonPointer(_) => {
                MaskKind::SameLengthFill
            }
            Self::ClientCert => MaskKind::Nothing,
            Self::Signed { .. } => MaskKind::SignatureSpan,
            Self::HandshakeFrames { .. } => MaskKind::BoundedPrefix,
        }
    }

    /// Whether resolving this location requires the whole body to have been spooled.
    ///
    /// The unit section of the design calls this the deepest pointer: when a signature covers the
    /// body, the body's end is the deepest pointer, and the unit does not open before it arrives.
    #[must_use]
    pub const fn needs_whole_body(&self) -> bool {
        matches!(
            self,
            Self::Signed {
                over: SignedOver::Body | SignedOver::Both
            }
        )
    }
}

/// Where a value can be found, either at arrival or in the decoded unit.
///
/// The second form exists for one purpose only — an idempotency key the kernel extracts from the
/// decoded body's span — and it is never available to an auth scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Location {
    /// Any of the arrival-resolvable forms.
    Arrival(ArrivalLocation),
    /// A pointer into the decoded unit's object notation. Idempotency only.
    UnitJsonPointer(&'static str),
}

/// Whether a replayed request is matched by reference or by body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ReplayMatch {
    /// The stored reference is compared.
    Reference,
    /// The stored body is compared.
    Body,
}

/// A claim's optional idempotency declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Idempotency {
    /// Where the client's key is found.
    pub location: Location,
    /// How a replay is matched.
    pub replay: ReplayMatch,
}

/// One claim: a transport, a selector, a scheme and an optional idempotency rule.
///
/// A claim is the only way a plane names a transport, and it names it as a claim, never as a
/// connection. The plane axis is blind to the transport axis in every other respect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Claim {
    /// The transport key this claim is made against.
    pub transport: &'static str,
    /// What the claim matches.
    pub selector: Selector,
    /// The credential scheme the claim's units authenticate under.
    pub scheme: &'static str,
    /// The alternatives a plane may narrow the scheme to at the authenticate step.
    pub scheme_alternatives: &'static [&'static str],
    /// The claim's idempotency rule, if it declares one.
    pub idempotency: Option<Idempotency>,
}

impl Claim {
    /// Whether two claims could ever match the same arriving bytes.
    ///
    /// Claims on different transports cannot collide, because bytes arrive on one transport. On
    /// the same transport the answer is the selectors' answer.
    #[must_use]
    pub fn overlaps(&self, other: &Claim) -> bool {
        self.transport == other.transport && self.selector.overlaps(&other.selector)
    }
}

impl Selector {
    /// The form of this selector, without its value.
    #[must_use]
    pub const fn form(&self) -> SelectorForm {
        match self {
            Self::ExactPath(_) => SelectorForm::ExactPath,
            Self::PrefixOneLevel(_) => SelectorForm::PrefixOneLevel,
            Self::Sni(_) => SelectorForm::Sni,
            Self::ClientCertSubject(_) => SelectorForm::ClientCertSubject,
            Self::PathPattern(_) => SelectorForm::PathPattern,
            Self::HeaderExact(_, _) => SelectorForm::HeaderExact,
            Self::HeaderPresent(_) => SelectorForm::HeaderPresent,
            Self::HeaderPrefix(_, _) => SelectorForm::HeaderPrefix,
            Self::PathSuffix(_) => SelectorForm::PathSuffix,
            Self::PathContains(_) => SelectorForm::PathContains,
            Self::StreamName(_) => SelectorForm::StreamName,
            Self::Alpn(_) => SelectorForm::Alpn,
            Self::Port(_) => SelectorForm::Port,
        }
    }

    /// Whether two selectors could ever match the same arriving bytes.
    ///
    /// Total over the cross-product of forms: every pair has an answer and no pair is left to a
    /// catch-all that panics. The rule has three tiers.
    ///
    /// Different families read different parts of the request, so both can be true of one request
    /// and the answer is that they overlap. Within the path family, the open-ended forms — a
    /// pattern with a variable or tail segment, a suffix, a substring — overlap anything else in
    /// the family, because a path exists that satisfies both; two closed forms are compared as
    /// strings. Within the header family the same shape applies, one level down: two selectors on
    /// *different* header names never collide, and on the same name the present, prefix and exact
    /// forms are compared by the widest of the two.
    ///
    /// Reflexive and symmetric by construction, and the fixtures assert both across every pair.
    #[must_use]
    pub fn overlaps(&self, other: &Selector) -> bool {
        let (a, b) = (self.form().family(), other.form().family());
        if a != b {
            // Different parts of the same request: both can be true at once.
            return true;
        }
        match a {
            SelectorFamily::Path => self.path_overlaps(other),
            SelectorFamily::Header => self.header_overlaps(other),
            SelectorFamily::Handshake => self.handshake_overlaps(other),
            SelectorFamily::Stream => match (self, other) {
                (Self::StreamName(x), Self::StreamName(y)) => x == y,
                _ => true,
            },
            SelectorFamily::Port => match (self, other) {
                (Self::Port(x), Self::Port(y)) => x == y,
                _ => true,
            },
        }
    }

    /// The path family's rule.
    fn path_overlaps(&self, other: &Selector) -> bool {
        match (self, other) {
            (Self::ExactPath(x), Self::ExactPath(y)) => x == y,
            (Self::ExactPath(p), Self::PrefixOneLevel(q))
            | (Self::PrefixOneLevel(q), Self::ExactPath(p)) => one_level_under(q, p),
            (Self::PrefixOneLevel(x), Self::PrefixOneLevel(y)) => x == y,
            (Self::ExactPath(p), Self::PathPattern(pat))
            | (Self::PathPattern(pat), Self::ExactPath(p)) => pattern_matches(pat, p),
            (Self::PathPattern(x), Self::PathPattern(y)) => patterns_overlap(x, y),
            (Self::ExactPath(p), Self::PathSuffix(s))
            | (Self::PathSuffix(s), Self::ExactPath(p)) => p.ends_with(s),
            (Self::ExactPath(p), Self::PathContains(s))
            | (Self::PathContains(s), Self::ExactPath(p)) => p.contains(s),
            // Every remaining path pair mixes at least one open-ended form with another
            // open-ended form: a path satisfying both always exists, so they overlap.
            _ => true,
        }
    }

    /// The header family's rule.
    fn header_overlaps(&self, other: &Selector) -> bool {
        let (n1, n2) = (self.header_name(), other.header_name());
        match (n1, n2) {
            (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b) => false,
            _ => match (self, other) {
                (Self::HeaderExact(_, x), Self::HeaderExact(_, y)) => x == y,
                (Self::HeaderExact(_, v), Self::HeaderPrefix(_, p))
                | (Self::HeaderPrefix(_, p), Self::HeaderExact(_, v)) => v.starts_with(p),
                (Self::HeaderPrefix(_, x), Self::HeaderPrefix(_, y)) => {
                    x.starts_with(y) || y.starts_with(x)
                }
                // A present claim overlaps anything on the same header.
                _ => true,
            },
        }
    }

    /// The handshake family's rule.
    fn handshake_overlaps(&self, other: &Selector) -> bool {
        match (self, other) {
            (Self::Sni(x), Self::Sni(y)) => x.eq_ignore_ascii_case(y),
            (Self::Alpn(x), Self::Alpn(y)) => x == y,
            (Self::ClientCertSubject(x), Self::ClientCertSubject(y)) => x == y,
            // A name, a protocol and a certificate subject are independent facts of one
            // handshake, so a connection satisfying both always exists.
            _ => true,
        }
    }

    /// The header name this selector reads, when it reads one.
    #[must_use]
    pub const fn header_name(&self) -> Option<&'static str> {
        match self {
            Self::HeaderExact(n, _) | Self::HeaderPresent(n) | Self::HeaderPrefix(n, _) => Some(n),
            _ => None,
        }
    }
}

/// Whether a path is exactly one segment under a prefix.
fn one_level_under(prefix: &str, path: &str) -> bool {
    let Some(rest) = path.strip_prefix(prefix) else {
        return false;
    };
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    !rest.is_empty() && !rest.contains('/')
}

/// Split a path into its non-empty segments.
fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|s| !s.is_empty())
}

/// Whether a pattern matches a concrete path.
fn pattern_matches(pattern: &[PathSeg], path: &str) -> bool {
    let mut segs = segments(path);
    for (i, seg) in pattern.iter().enumerate() {
        match seg {
            PathSeg::Tail => {
                // A tail is the last segment of a pattern and swallows whatever remains,
                // including nothing.
                let _ = i;
                return true;
            }
            PathSeg::Lit(lit) => match segs.next() {
                Some(s) if s == *lit => {}
                _ => return false,
            },
            PathSeg::Var => {
                if segs.next().is_none() {
                    return false;
                }
            }
        }
    }
    segs.next().is_none()
}

/// Whether two patterns can match one path.
///
/// Per segment, a variable overlaps any literal and a tail overlaps every remaining segment, both
/// conservatively — the design says so in as many words.
fn patterns_overlap(a: &[PathSeg], b: &[PathSeg]) -> bool {
    let mut i = 0;
    loop {
        match (a.get(i), b.get(i)) {
            (None, None) => return true,
            (Some(PathSeg::Tail), _) | (_, Some(PathSeg::Tail)) => return true,
            (None, _) | (_, None) => return false,
            (Some(PathSeg::Lit(x)), Some(PathSeg::Lit(y))) if x != y => return false,
            // A variable segment overlaps any single segment.
            _ => {}
        }
        i += 1;
    }
}
