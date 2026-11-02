//! The closed grammars: claims, selectors, arrival locations and locations.

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
    /// ONE OR MORE segments of any value, spelled `{name+}`: a placeholder that spans the arriving
    /// path's own `/` (a raw one, as an unencoded identifier carries, or none, as an encoded one
    /// does), then hands the rest of the pattern what follows. At most one per pattern.
    Plus,
}

/// One segment of a path pattern as the matcher reads it: a literal borrowed for the call, so a
/// pattern spelled in a request-time string is matched without making it `'static`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegRef<'a> {
    /// A literal segment, matched exactly.
    Lit(&'a str),
    /// One segment of any value.
    Var,
    /// Every remaining segment.
    Tail,
    /// One or more segments of any value ([`PathSeg::Plus`]).
    Plus,
}

impl PathSeg {
    /// This segment as the matcher reads it.
    #[must_use]
    pub const fn seg_ref(&self) -> SegRef<'static> {
        match *self {
            PathSeg::Lit(l) => SegRef::Lit(l),
            PathSeg::Var => SegRef::Var,
            PathSeg::Tail => SegRef::Tail,
            PathSeg::Plus => SegRef::Plus,
        }
    }
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

impl MaskKind {
    /// Every kind, in one place: the closed set the arrival gate switches on.

    pub const ALL: [MaskKind; 4] = [
        MaskKind::SameLengthFill,
        MaskKind::Nothing,
        MaskKind::SignatureSpan,
        MaskKind::BoundedPrefix,
    ];
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
    /// One variable segment of the matched path pattern, by index among the pattern's variables.
    ///
    /// The index counts the pattern's non-literal segments left to right from zero. A
    /// [`PathSeg::Var`] is one variable and resolves to the one segment it matched; a
    /// [`PathSeg::Tail`] is also one variable, and resolves to the FIRST segment it matched,
    /// because a tail's later segments are not addressable by a fixed index. An index past the
    /// pattern's variables resolves to nothing, which is a missing location and not an error.
    ///
    /// The claim grammar already makes the kernel the owner of `PathPattern` and of its
    /// per-segment overlap rule, so the segment index exists before any plane is chosen and is
    /// resolvable at arrival like every other form here. It is the form a protocol that names the
    /// priced thing in the request target rather than in the body needs; without it such a protocol
    /// can only be located by having the arrival path copy the value into the body first, which is
    /// a kernel-side body rewrite the lean-core scan would have to allow.
    PathSegment(u8),
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
            Self::Header(_)
            | Self::Query(_)
            | Self::PathSegment(_)
            | Self::FirstFrameJsonPointer(_) => MaskKind::SameLengthFill,
            Self::ClientCert => MaskKind::Nothing,
            Self::Signed { .. } => MaskKind::SignatureSpan,
            Self::HandshakeFrames { .. } => MaskKind::BoundedPrefix,
        }
    }

    /// Whether resolving this location requires the whole body to have been spooled.

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
    /// The credential scheme the claim's units authenticate under, where they carry one.
    ///
    /// `None` says the claim's units carry NO credential: they admit the anonymous principal
    /// without consulting a scheme at all. A deliberately open surface — a discovery document, a
    /// callback anyone may post to — is a property of the claim, decided at registration and
    /// checked at boot.
    ///
    /// It is deliberately NOT a scheme key the registry happens to know. The authenticate step may
    /// only narrow within a claim's declared alternatives, and a scheme key meaning "none" would be
    /// one alternative among others: a plane could then narrow an authenticated claim down to
    /// anonymous and the check would pass, because the key IS declared. That is the check failing
    /// to check the one thing it exists for. With the absence carried on the claim, a claim that
    /// declares a scheme has alternatives to narrow within and the check runs unchanged, and a
    /// claim that declares none has nothing to narrow to at all.
    pub scheme: Option<&'static str>,
    /// The alternatives a plane may narrow the scheme to at the authenticate step.
    ///
    /// Empty when the claim declares no scheme: there is nothing to narrow.
    pub scheme_alternatives: &'static [&'static str],
    /// The claim's idempotency rule, if it declares one.
    pub idempotency: Option<Idempotency>,
}

/// Declare an ordered detection ladder and the claim list that goes with it, from one table.
///
/// A claim carries exactly one selector, and that rule is right: a boot that has to decide whether
/// two claims could match the same bytes cannot do it through an unexplained disjunction. But a
/// plane whose protocol detection is a fourteen-rung ladder then has two dozen claims, and a
/// constant cannot loop over a constant, so both the ladder and the narrower `CLAIMS` list get
/// transcribed by hand — twice, by index, with the rung number in a comment. That is a legibility
/// cost rather than a correctness one, and this is the fix for it.
///
/// The row type is the caller's own, and it must have the three fields the invocation fills:
/// `rung`, `dialect` and `claim`. The builder is the caller's own `const fn` from a selector to a
/// claim, so the scheme, alternatives and idempotency stay where the plane declares them once.
/// Ordinary comments between rows survive, because a macro invocation is still source.
#[macro_export]
macro_rules! claims_from_ladder {
    (
        $(#[$ladder_doc:meta])* $ladder:ident,
        $(#[$claims_doc:meta])* $claims:ident,
        $row:ident, $build:ident,
        $($rung:literal => $dialect:literal, $selector:expr),+ $(,)?
    ) => {
        $(#[$ladder_doc])*
        pub const $ladder: &[$row] = &[
            $($row { rung: $rung, dialect: $dialect, claim: $build($selector) },)+
        ];

        $(#[$claims_doc])*
        pub const $claims: &[$crate::grammar::Claim] = &[$($build($selector),)+];
    };
}

impl Claim {
    /// Whether this claim's units carry no credential at all.
    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        self.scheme.is_none()
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

    #[must_use]
    pub fn overlaps(&self, other: &Selector) -> bool {
        let (a, b) = (self.form().family(), other.form().family());
        if a != b {
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

            (Self::PrefixOneLevel(prefix), Self::PathPattern(pat))
            | (Self::PathPattern(pat), Self::PrefixOneLevel(prefix)) => {
                prefix_overlaps_pattern(prefix, pat)
            }

            (Self::PathSuffix(x), Self::PathSuffix(y)) => x.ends_with(y) || y.ends_with(x),
            (Self::PathSuffix(s), Self::PathPattern(pat))
            | (Self::PathPattern(pat), Self::PathSuffix(s)) => {
                fragment_overlaps_pattern(s, pat, true)
            }
            (Self::PathContains(s), Self::PathPattern(pat))
            | (Self::PathPattern(pat), Self::PathContains(s)) => {
                fragment_overlaps_pattern(s, pat, false)
            }

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

#[must_use]
pub fn one_level_under(prefix: &str, path: &str) -> bool {
    let Some(rest) = path.strip_prefix(prefix).and_then(|r| r.strip_prefix('/')) else {
        return false;
    };
    !rest.is_empty() && !rest.contains('/')
}

/// Split a path into its non-empty segments.
fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|s| !s.is_empty())
}

/// Whether a pattern matches a concrete path.

#[must_use]
pub fn pattern_matches(pattern: &[PathSeg], path: &str) -> bool {
    segs_match(pattern.iter().map(PathSeg::seg_ref), path)
}

/// [`pattern_matches`] over borrowed segments: the one body both read. Allocation-free: a

#[must_use]
pub fn segs_match<'a, I>(pattern: I, path: &str) -> bool
where
    I: IntoIterator<Item = SegRef<'a>>,
    I::IntoIter: Clone,
{
    walk(pattern.into_iter(), path)
}

/// The path's next non-empty segment and what follows it, or `None` when none is left.
fn next_seg(path: &str) -> Option<(&str, &str)> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return None;
    }
    Some(
        path.find('/')
            .map_or((path, ""), |i| (&path[..i], &path[i..])),
    )
}

/// [`segs_match`]'s walk over the pattern's remaining segments and the path's remaining bytes.
fn walk<'a>(mut pattern: impl Iterator<Item = SegRef<'a>> + Clone, mut path: &str) -> bool {
    while let Some(seg) = pattern.next() {
        match seg {
            SegRef::Tail => return true,
            SegRef::Lit(lit) => match next_seg(path) {
                Some((s, rest)) if s == lit => path = rest,
                _ => return false,
            },
            SegRef::Var => match next_seg(path) {
                Some((_, rest)) => path = rest,
                None => return false,
            },

            SegRef::Plus => {
                let Some((_, mut rest)) = next_seg(path) else {
                    return false;
                };
                loop {
                    if walk(pattern.clone(), rest) {
                        return true;
                    }
                    match next_seg(rest) {
                        Some((_, more)) => rest = more,
                        None => return false,
                    }
                }
            }
        }
    }
    next_seg(path).is_none()
}

/// Whether two patterns can match one path.

fn patterns_overlap(a: &[PathSeg], b: &[PathSeg]) -> bool {
    tokens_overlap(&tokens(a), &tokens(b))
}

/// One step of a pattern for [`tokens_overlap`]: a literal segment, one segment of any value, or
/// any number of segments (none included).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tok {
    Lit(&'static str),
    One,
    Many,
}

/// A pattern as [`Tok`]s: a variable is one segment, a tail any number, a plus one then any number.
fn tokens(pattern: &[PathSeg]) -> Vec<Tok> {
    let mut out = Vec::with_capacity(pattern.len() + 1);
    for seg in pattern {
        match *seg {
            PathSeg::Lit(l) => out.push(Tok::Lit(l)),
            PathSeg::Var => out.push(Tok::One),
            PathSeg::Tail => out.push(Tok::Many),
            PathSeg::Plus => out.extend([Tok::One, Tok::Many]),
        }
    }
    out
}

/// Whether some path is spelled by both token runs.
fn tokens_overlap(a: &[Tok], b: &[Tok]) -> bool {
    match (a.split_first(), b.split_first()) {
        (None, None) => true,
        (Some((Tok::Many, ra)), _) => {
            tokens_overlap(ra, b) || b.split_first().is_some_and(|(_, rb)| tokens_overlap(a, rb))
        }
        (_, Some((Tok::Many, rb))) => {
            tokens_overlap(a, rb) || a.split_first().is_some_and(|(_, ra)| tokens_overlap(ra, b))
        }
        (None, Some(_)) | (Some(_), None) => false,
        (Some((x, ra)), Some((y, rb))) => {
            let one = match (x, y) {
                (Tok::Lit(p), Tok::Lit(q)) => p == q,
                _ => true,
            };
            one && tokens_overlap(ra, rb)
        }
    }
}

/// Whether a one-level prefix and a pattern can both match one path.

fn prefix_overlaps_pattern(prefix: &str, pattern: &[PathSeg]) -> bool {
    if pattern.iter().any(|s| matches!(s, PathSeg::Plus)) {
        return true;
    }
    let mut i = 0usize;
    for literal in segments(prefix) {
        match pattern.get(i) {
            None => return false,
            Some(PathSeg::Tail | PathSeg::Plus) => return true,
            Some(PathSeg::Var) => {}
            Some(PathSeg::Lit(l)) if *l == literal => {}
            Some(PathSeg::Lit(_)) => return false,
        }
        i += 1;
    }
    match pattern.get(i) {
        Some(PathSeg::Tail) => true,

        Some(_) => pattern.len() == i + 1 || matches!(pattern.get(i + 1), Some(PathSeg::Tail)),
        None => false,
    }
}

/// Whether a path matching this pattern can carry this literal — anywhere in it, or, when `at_end`,

fn fragment_overlaps_pattern(literal: &str, pattern: &[PathSeg], at_end: bool) -> bool {
    if pattern
        .iter()
        .any(|s| matches!(s, PathSeg::Tail | PathSeg::Plus))
    {
        return true;
    }
    let piece = |k: usize| literal.split('/').nth(k).unwrap_or("");
    let slashes = literal.split('/').count() - 1;
    let n = pattern.len();

    if slashes == 0 {
        let fits = |s: &PathSeg| match s {
            PathSeg::Lit(l) if at_end => l.ends_with(literal),
            PathSeg::Lit(l) => l.contains(literal),
            _ => true,
        };
        return if at_end {
            pattern.last().is_some_and(fits)
        } else {
            pattern.iter().any(fits)
        };
    }
    if (1..slashes).any(|k| piece(k).is_empty()) || (at_end && piece(slashes).is_empty()) {
        return true;
    }

    let whole = |i: usize, want: &str| match pattern.get(i) {
        Some(PathSeg::Lit(l)) => *l == want,
        Some(_) => !want.is_empty(),
        None => false,
    };

    (0..=n).any(|start| {
        let head = piece(0);
        let head_ok = head.is_empty()
            || match pattern.get(start) {
                Some(PathSeg::Lit(l)) => l.ends_with(head),
                Some(_) => true,
                None => false,
            };
        let first = if start == n { 0 } else { start + 1 };
        let landing = first + slashes - 1;
        let last = piece(slashes);
        head_ok
            && (1..slashes).all(|k| whole(first + k - 1, piece(k)))
            && if at_end {
                landing + 1 == n && whole(landing, last)
            } else if last.is_empty() {
                landing <= n
            } else {
                match pattern.get(landing) {
                    Some(PathSeg::Lit(l)) => l.starts_with(last),
                    Some(_) => true,
                    None => false,
                }
            }
    })
}
