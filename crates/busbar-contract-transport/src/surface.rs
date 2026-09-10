// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plane's SERVED SURFACE, as data a transport can mount without knowing what it is.
//!
//! ## The hole this fills
//!
//! A plane already declares what it CLAIMS — `PlaneMeta::CLAIMS` is a list of selectors, and the
//! kernel uses it to decide which plane a request belongs to. That is enough to route a request and
//! nowhere near enough to SERVE one. A transport that has to mount a protocol needs to know the
//! things a claim deliberately leaves out: which operation a target names, what the request method
//! is, whether the answer is one document or a run of them, what media type goes on each direction,
//! and — for the binding where the target carries no path at all — which service descriptor and
//! method spell the call.
//!
//! Every one of those was, until now, written inside a protocol's own server. That is what made a
//! wire protocol a crate: not the bytes, which are the plane's, but the fifteen or so facts about
//! how the bytes are addressed, which had nowhere to be declared. They are declared here, generically,
//! and the transports below read them without naming a protocol.
//!
//! ## Plane-agnostic, and that is a rule rather than an aspiration
//!
//! Nothing in this module names a protocol, a dialect or a plane. Every string is the DECLARER's:
//! a binding name, a path template, a request method, a service descriptor. The vocabulary is the
//! same shape for a protocol whose operations are named by their target, for one whose operations
//! are named by a member of the request document, and for one whose operations are named by a
//! service descriptor — because those three are the only ways an operation has ever been addressed,
//! and a fourth would be a new [`Dispatch`] arm rather than a new crate.
//!
//! ## Where the strings come from
//!
//! From the declaring plane's own constants, not from here and not from the transport. A path
//! template written twice is two paths that will disagree, and the one that disagrees quietly is the
//! one that answers 404 to a conformant client. The declaration is the single copy; the transport
//! matches against it and the plane's claims are built from it.

use core::fmt;

/// Whether an operation's answer is one document or a run of them.
///
/// Load-bearing on both sides. A transport reads it to decide whether the response leaves as a
/// single body or as a stream that stays open, and the loop reads it to decide whether the unit is
/// complete in one frame or holds its direction open. A protocol that got this wrong for one
/// operation would answer a streaming call with a closed body — the client waits for events on a
/// connection nothing will write to again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Answering {
    /// One request, one answer, and the exchange is over.
    Unary,
    /// One request, a run of answers, ended by the last of them.
    Stream,
}

/// Whether a surface demands a credential.
///
/// Two values and no third: a surface either sits behind the node's credential bar or is
/// deliberately open. "Open" is a declaration and not an omission — the discovery documents a client
/// reads BEFORE it has a token are open because demanding a credential to learn which credential to
/// present is circular, and a surface that is open by accident is indistinguishable from one that is
/// open on purpose unless it says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Bar {
    /// The caller presents a credential, and the authenticate step resolves it.
    Credential,
    /// The caller presents none, by declaration.
    Open,
}

/// How one binding names an operation.
///
/// The three arms are the three ways an operation has ever been addressed on a wire, and the arm a
/// dispatch takes is what tells a transport where to look. Nothing here says which protocol: a
/// [`Dispatch::Target`] is a path and a method whatever grammar wrote them, and a
/// [`Dispatch::Service`] is a descriptor and a method whatever generated it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Dispatch {
    /// The request TARGET names the operation: a path template and the request method beside it.
    ///
    /// `path` is a template in the one grammar this vocabulary defines — literal segments and
    /// `{name}` captures, matched by [`match_target`]. It is the declarer's own string, byte for
    /// byte, because it is simultaneously the route a transport mounts, the selector a claim is
    /// built from and the URL a published document advertises, and those three cannot be allowed
    /// to be three different strings.
    Target {
        /// The path template, captures included.
        path: &'static str,
        /// The request method this row answers, spelled as the wire spells it.
        method: &'static str,
        /// Whether this surface demands a credential.
        bar: Bar,
    },
    /// A MEMBER of the request document names the operation.
    ///
    /// WHERE the document is posted is the BINDING's fact and not this row's: one envelope binding
    /// serves every one of its operations at the same mount, and a protocol whose mount has two
    /// accepted spellings — the trailing separator a great many HTTP clients send is the ordinary
    /// case — would otherwise need one row per operation per spelling, which is a cross-product
    /// nobody can read and every one of whose cells can be forgotten. So the mounts are declared
    /// once on [`BindingDecl::mounts`] and this row names the binding.
    ///
    /// `member` is the document member the name is read out of, and `name` is the value that means
    /// this operation. Declaring the member rather than assuming one is what keeps this arm honest
    /// for any envelope, not just the one this vocabulary was first written against.
    Document {
        /// The binding whose mounts this document is posted to.
        binding: &'static str,
        /// The request method the document is posted with.
        method: &'static str,
        /// The document member the operation's name is read from.
        member: &'static str,
        /// The value of that member which means THIS operation.
        name: &'static str,
        /// Whether this surface demands a credential.
        bar: Bar,
    },
    /// A SERVICE DESCRIPTOR names the operation: the framed binding's shape.
    ///
    /// The target of a framed call is derived by the client from the descriptor rather than chosen,
    /// which is why this cannot be a [`Dispatch::Target`] with a literal path: the transport builds
    /// the path from the two names, and a declaration that wrote the path down instead would drift
    /// from the descriptor the client is reading.
    Service {
        /// The fully-qualified service name.
        service: &'static str,
        /// The method within it.
        method: &'static str,
        /// Whether this surface demands a credential.
        bar: Bar,
    },
    /// THE BINDING ITSELF names the operation, because after the upgrade nothing else can.
    ///
    /// The duplex kind, beside the three request/answer ones, and it is a kind of its own rather
    /// than a spelling of [`Dispatch::Document`] because the two differ in the one fact a mount
    /// acts on. A document row promises that a member of an arriving document names the operation,
    /// and a reader can go and read that member on every request. A session has no such member and
    /// no such request: there is ONE upgrade, it carries a target and a method, and from the
    /// protocol switch onwards the wire has neither. What the frames after it mean is the plane's,
    /// decided from the session's own accumulated state, and no dispatch row could ever match one.
    ///
    /// So this row declares exactly the three facts a mount needs BEFORE the upgrade, and nothing
    /// it could not have afterwards: which binding a session may be opened on — the binding's own
    /// [`BindingDecl::mounts`] are WHERE — the method the upgrade arrives with, and whether the
    /// upgrade has to carry a credential. That bar is the last one this wire can demand, which is
    /// why it is the whole session's rather than one request's.
    ///
    /// A plane with no duplex kind available had to declare a session as a document row instead,
    /// which puts a `member` and a `name` on it that nothing resolves and nothing could resolve. A
    /// mount reading such a surface cannot tell a session mount from an envelope endpoint that
    /// happens to be carried by a duplex-capable transport — and would open a session on either.
    Duplex {
        /// The binding a session is opened on; its [`BindingDecl::mounts`] are where.
        binding: &'static str,
        /// The request method the upgrade arrives with.
        method: &'static str,
        /// Whether the upgrade has to carry a credential.
        ///
        /// The session's only chance to demand one: a session presents a credential once, on the
        /// upgrade, and never again.
        bar: Bar,
    },
}

impl Dispatch {
    /// Whether this dispatch demands a credential.
    #[must_use]
    pub fn bar(&self) -> Bar {
        match self {
            Dispatch::Target { bar, .. }
            | Dispatch::Document { bar, .. }
            | Dispatch::Service { bar, .. }
            | Dispatch::Duplex { bar, .. } => *bar,
        }
    }
}

/// One operation of a plane's served surface, and every way it can be addressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Operation {
    /// The operation class this row is, as the declaring plane spells it.
    ///
    /// A string rather than a typed id, because this crate sits below the contract and may not name
    /// the contract's ids; the mount hands it back to the plane, which is the only thing entitled to
    /// interpret it.
    pub op: &'static str,
    /// Every way this operation can be addressed, one per binding it is reachable on.
    pub dispatch: &'static [Dispatch],
    /// Whether the answer is one document or a run of them.
    pub answering: Answering,
    /// The media type a request body of this operation carries.
    pub request_media: &'static str,
    /// The media type an answer to it carries.
    ///
    /// Not always the request's: a streamed answer to a document request is the ordinary case where
    /// the two differ, and a transport that assumed one media type for both would put the wrong one
    /// on every streamed response.
    pub response_media: &'static str,
}

/// One wire binding a surface is served under.
///
/// The name is the declarer's own word for the binding and is what a published document advertises;
/// `transport` is the registry key of the transport that carries it, which is how a mount knows
/// which of its bindings it is responsible for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct BindingDecl {
    /// The binding's own name, as a published document spells it.
    pub name: &'static str,
    /// The registry key of the transport that carries it.
    pub transport: &'static str,
    /// Where this binding is addressed — its mount PATTERNS.
    ///
    /// A LIST, not one path, because a mount routinely has more than one accepted spelling and every
    /// one of them has to answer. An HTTP client handed `http://host/a2a` as a BASE resolves a
    /// request for `/` against it and sends `/a2a/`, so a mount declared only without the separator
    /// leaves the single most likely spelling of its own endpoint answering 404. Declaring the set
    /// is what makes that a data question rather than a route somebody has to remember to add.
    ///
    /// PATTERNS, in the one grammar this vocabulary already defines for a path: literal segments and
    /// whole-segment `{name}` captures, matched by [`match_target`] and checked by
    /// [`mount_is_wellformed`]. Every mount written before this was a pattern with no capture in it,
    /// and an all-literal pattern matches exactly the one target it spells — so nothing that was
    /// declared as a literal moved.
    ///
    /// The capture is what a SESSION mount could not express and needed to. A request/answer
    /// operation is addressed by [`Dispatch::Target`] and has carried a template since this
    /// vocabulary was written; a session is addressed by its binding's mounts and by nothing else,
    /// so a published URL with an identifier in it — `/v1/realtime/telephony/{call_id}` is the
    /// tree's own — was a URL a binding could not declare at all. The declaration had the choice of
    /// a different URL or a literal per live call, and both of those are the served surface changing
    /// to suit the vocabulary rather than the other way round.
    ///
    /// What a capture yields is the DECLARER's: [`duplex_binding_at`] hands back the
    /// [`Capture`] list a matched pattern produced, in declaration order, and a mount publishes
    /// them as facts under their declared names — the same thing the request/answer mount already
    /// does with a template's captures.
    ///
    /// Empty for a binding whose operations are named by their target or by a service descriptor.
    pub mounts: &'static [&'static str],
}

/// Everything a transport needs to serve a plane, and nothing that says which plane it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct WireSurface {
    /// The bindings this surface is served under.
    pub bindings: &'static [BindingDecl],
    /// The operations, in the order a target is matched in.
    ///
    /// The order is load-bearing and is the declarer's: an exact path sitting above a template that
    /// would also match it is how a protocol says which one wins, and a mount that sorted this list
    /// would be deciding a precedence the protocol already decided.
    pub operations: &'static [Operation],
}

/// A surface a mount will not boot on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceError {
    /// Two operations are addressed identically, so a request naming that address is ambiguous.
    ///
    /// Not a warning. A mount handed two rows for one address either answers with the first and
    /// silently never reaches the second, or answers with whichever the map iterated to — and both
    /// are a served surface nobody declared.
    DuplicateAddress {
        /// The operation the second row belongs to.
        op: &'static str,
    },
    /// A path template is not in the template grammar: an empty segment, or a capture that is not a
    /// whole segment.
    MalformedTemplate {
        /// The template as declared.
        path: &'static str,
    },
    /// An operation declares no way to address it at all, so nothing can ever reach it.
    Unaddressable {
        /// The operation.
        op: &'static str,
    },
    /// The surface declares no binding, so there is nothing to mount it on.
    NoBinding,
    /// A dispatch names a binding the surface does not declare.
    ///
    /// The other direction of the declaration rule, and the one a mount cannot survive: a document
    /// row naming a binding with no mounts is an operation posted to nowhere, and it would report as
    /// "that method does not exist" to every caller that asked for it correctly.
    UnknownBinding {
        /// The operation the dispatch belongs to.
        op: &'static str,
        /// The binding it named.
        binding: &'static str,
    },
    /// A duplex row names a binding that declares no mount, so no session could ever be opened.
    ///
    /// Distinct from [`SurfaceError::UnknownBinding`] because the binding EXISTS and a published
    /// document would advertise it. A duplex binding's mounts are the only way a session is
    /// addressed — there is no template and no descriptor to fall back to — so a mountless one is a
    /// binding a client can read about and can never reach.
    NoDuplexMount {
        /// The operation the dispatch belongs to.
        op: &'static str,
        /// The binding it named.
        binding: &'static str,
    },
    /// A duplex row sits on an operation that says it answers once.
    ///
    /// A contradiction rather than a slip: [`Answering::Unary`] tells a mount to close the direction
    /// after the first thing it writes, and a session closed at its first answer is not a session.
    /// The declaration would type-check and the outage would be silent, which is why it is refused
    /// at boot instead.
    DuplexNotStreaming {
        /// The operation.
        op: &'static str,
    },
}

impl fmt::Display for SurfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateAddress { op } => write!(
                f,
                "the operation `{op}` is addressed the same way as an earlier one, so a request \
                 naming that address is ambiguous and one of the two could never be reached"
            ),
            Self::MalformedTemplate { path } => write!(
                f,
                "the path template `{path}` is not in the template grammar: a capture is a whole \
                 segment spelled `{{name}}`, and no segment may be empty"
            ),
            Self::Unaddressable { op } => write!(
                f,
                "the operation `{op}` declares no dispatch, so nothing on any binding could ever \
                 reach it"
            ),
            Self::NoBinding => write!(
                f,
                "the surface declares no binding, so there is no transport to mount it on"
            ),
            Self::UnknownBinding { op, binding } => write!(
                f,
                "the operation `{op}` is dispatched on the binding `{binding}`, which this surface \
                 does not declare — so it is posted to nowhere and reports as a method that does \
                 not exist"
            ),
            Self::NoDuplexMount { op, binding } => write!(
                f,
                "the operation `{op}` opens a session on the binding `{binding}`, which declares no \
                 mount — a session is addressed by its binding's mounts and by nothing else, so \
                 there is no target any client could open one at"
            ),
            Self::DuplexNotStreaming { op } => write!(
                f,
                "the operation `{op}` opens a session and answers `Unary`, which tells a mount to \
                 close the direction after the first frame it writes — a session cut at its first \
                 answer"
            ),
        }
    }
}

impl std::error::Error for SurfaceError {}

/// One capture a matched target yielded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capture<'t> {
    /// The capture's declared name, without the braces.
    pub name: &'t str,
    /// What stood in its place in the request target.
    pub value: &'t str,
}

/// The most captures one path template may declare.
///
/// A fixed ceiling rather than a growing vector: this runs once per arriving request, and a
/// template deep enough to exceed it is one no protocol in the tree writes. A template that does is
/// refused by [`check_surface`] at boot rather than truncated at serve time.
pub const MAX_CAPTURES: usize = 8;

/// Match one request target against one path template.
///
/// The grammar is small and closed: a template is `/`-separated segments, a segment is either a
/// literal or `{name}`, and a capture matches exactly one non-empty segment. Query and fragment are
/// cut from the target before matching, because neither is part of the path and a protocol that
/// wanted one would declare it as its own fact.
///
/// Returns the captures in declaration order, or `None` when the target is not this template.
#[must_use]
pub fn match_target<'t>(template: &'t str, target: &'t str) -> Option<Vec<Capture<'t>>> {
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let mut captures = Vec::new();
    let mut want = template.split('/');
    let mut got = path.split('/');
    loop {
        match (want.next(), got.next()) {
            (None, None) => return Some(captures),
            (Some(w), Some(g)) => {
                if let Some(name) = w.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                    // A capture matches ONE non-empty segment. An empty one would let
                    // `/tasks//configs` match `/tasks/{id}/configs` and reach a handler with no
                    // identifier at all, which is the shape that turns a missing argument into a
                    // scan of everything.
                    if g.is_empty() || captures.len() == MAX_CAPTURES {
                        return None;
                    }
                    captures.push(Capture { name, value: g });
                } else if w != g {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

/// Whether a path template is in the grammar [`match_target`] reads.
#[must_use]
pub fn template_is_wellformed(template: &str) -> bool {
    if !template.starts_with('/') {
        return false;
    }
    let mut captures = 0;
    for (i, seg) in template.split('/').enumerate() {
        // The leading empty segment is the one `/` produces and is the only empty one allowed.
        if i == 0 {
            continue;
        }
        if seg.is_empty() {
            return false;
        }
        let opens = seg.starts_with('{');
        let closes = seg.ends_with('}');
        if opens != closes {
            return false;
        }
        if opens {
            captures += 1;
            if seg.len() <= 2 || captures > MAX_CAPTURES {
                return false;
            }
        } else if seg.contains('{') || seg.contains('}') {
            return false;
        }
    }
    true
}

/// Whether a mount pattern is in the grammar [`match_target`] reads.
///
/// The same grammar [`template_is_wellformed`] holds a [`Dispatch::Target`] template to, minus one
/// rule: an EMPTY segment is legitimate here and is refused there. `/a2a/` is a mount an HTTP client
/// resolving `/` against a base sends and a mount that has to answer, and it ends in an empty
/// segment; a template that ended in one would be an operation addressed at a path with a blank
/// segment in it, which no protocol in the tree writes.
///
/// Everything else is held: a mount starts at the root, a capture is a WHOLE segment spelled
/// `{name}` with a name in it, a segment that carries a brace and is not a whole capture is a
/// pattern somebody meant to write a capture into and did not, and no pattern may declare more than
/// [`MAX_CAPTURES`] of them.
#[must_use]
pub fn mount_is_wellformed(mount: &str) -> bool {
    if !mount.starts_with('/') {
        return false;
    }
    let mut captures = 0;
    for (i, seg) in mount.split('/').enumerate() {
        // The leading empty segment is the one `/` produces; a later empty one is the trailing
        // separator spelling, which is the case this grammar exists to keep declarable.
        if i == 0 || seg.is_empty() {
            continue;
        }
        let opens = seg.starts_with('{');
        let closes = seg.ends_with('}');
        if opens != closes {
            return false;
        }
        if opens {
            captures += 1;
            if seg.len() <= 2 || captures > MAX_CAPTURES {
                return false;
            }
        } else if seg.contains('{') || seg.contains('}') {
            return false;
        }
    }
    true
}

/// The address one dispatch occupies, as the duplicate check compares them.
///
/// Two dispatches collide when a request could name both. For a target that is the template and the
/// method; for a document it is the mount, the method and the name; for a service it is the two
/// names. Comparing the whole dispatch instead would let two rows differing only in their credential
/// bar both mount, which is a surface where one address answers with a credential demanded and
/// without it depending on which row matched first.
fn address_of(d: &Dispatch) -> (&'static str, &'static str, &'static str) {
    match d {
        Dispatch::Target { path, method, .. } => (path, method, ""),
        Dispatch::Document {
            binding,
            method,
            name,
            ..
        } => (binding, method, name),
        Dispatch::Service {
            service, method, ..
        } => (service, method, ""),
        // A session is addressed by its BINDING, so a binding carries at most one duplex row per
        // method — a second would be two credential bars for one upgrade, and which one answered
        // would be whichever row the walk happened to reach first.
        Dispatch::Duplex {
            binding, method, ..
        } => (binding, method, DUPLEX_ADDRESS),
    }
}

/// The third component of a duplex row's address.
///
/// A sentinel rather than the empty string the target and service kinds use, because a duplex row's
/// first component is a BINDING name and a service row's is a SERVICE name, and those are not one
/// namespace. Without it, a surface that spelled a service exactly as it spelled a binding would
/// report a duplicate address between two rows on two different wires — rows no single request could
/// ever name both of. It is not a name and is never shown to anyone: the NUL makes it unspellable as
/// a declaration, which is what keeps it from colliding with a real one.
const DUPLEX_ADDRESS: &str = "\0duplex";

/// The boot check over a declared surface: every operation is reachable, no two are reachable the
/// same way, and every template is in the grammar.
///
/// Run once, when the mount is built, and before a byte is accepted. Each of the three is a
/// declaration that was a comment before this ran: a template nothing parsed, an ordering nothing
/// checked, an operation nothing could reach.
///
/// # Errors
///
/// The surface declares no binding, an operation declares no dispatch, a template is not in the
/// grammar, or two dispatches occupy one address.
pub fn check_surface(surface: &WireSurface) -> Result<(), SurfaceError> {
    if surface.bindings.is_empty() {
        return Err(SurfaceError::NoBinding);
    }
    for binding in surface.bindings {
        for mount in binding.mounts {
            // A mount is a PATTERN, in the same grammar a target template is written in and with
            // one rule relaxed: `/a2a/` ends in an empty segment and is a legitimate spelling of a
            // mount, which is exactly the case a template may not have. See [`mount_is_wellformed`].
            if !mount_is_wellformed(mount) {
                return Err(SurfaceError::MalformedTemplate { path: mount });
            }
        }
    }
    let mut seen: Vec<(&'static str, &'static str, &'static str)> = Vec::new();
    for operation in surface.operations {
        if operation.dispatch.is_empty() {
            return Err(SurfaceError::Unaddressable { op: operation.op });
        }
        for d in operation.dispatch {
            if let Dispatch::Target { path, .. } = d {
                if !template_is_wellformed(path) {
                    return Err(SurfaceError::MalformedTemplate { path });
                }
            }
            if let Dispatch::Document { binding, .. } = d {
                if !surface.bindings.iter().any(|b| b.name == *binding) {
                    return Err(SurfaceError::UnknownBinding {
                        op: operation.op,
                        binding,
                    });
                }
            }
            if let Dispatch::Duplex { binding, .. } = d {
                // The same declaration rule as a document row, and then the one extra thing a
                // session needs that a posted document does not: a binding a session is opened on
                // has to say WHERE. A document row can be posted at a mount the binding shares with
                // its siblings; a session has no second way to be addressed at all.
                let Some(decl) = surface.bindings.iter().find(|b| b.name == *binding) else {
                    return Err(SurfaceError::UnknownBinding {
                        op: operation.op,
                        binding,
                    });
                };
                if decl.mounts.is_empty() {
                    return Err(SurfaceError::NoDuplexMount {
                        op: operation.op,
                        binding,
                    });
                }
                if operation.answering != Answering::Stream {
                    return Err(SurfaceError::DuplexNotStreaming { op: operation.op });
                }
            }
            let address = address_of(d);
            if seen.contains(&address) {
                return Err(SurfaceError::DuplicateAddress { op: operation.op });
            }
            seen.push(address);
        }
    }
    Ok(())
}

/// Find the operation a request target and method address, in the surface's own order.
///
/// The order is the declarer's and is not re-derived: most-specific-first is how a protocol says
/// which of two overlapping templates wins, and the first match is therefore the answer. Returns the
/// operation, the dispatch that matched and the captures it yielded.
#[must_use]
pub fn resolve_target<'s>(
    surface: &'s WireSurface,
    target: &'s str,
    method: &str,
) -> Option<(&'s Operation, &'s Dispatch, Vec<Capture<'s>>)> {
    for operation in surface.operations {
        for d in operation.dispatch {
            let Dispatch::Target {
                path, method: want, ..
            } = d
            else {
                continue;
            };
            if !want.eq_ignore_ascii_case(method) {
                continue;
            }
            if let Some(captures) = match_target(path, target) {
                return Some((operation, d, captures));
            }
        }
    }
    None
}

/// Find the operation a framed call's service and method address.
#[must_use]
pub fn resolve_service<'s>(
    surface: &'s WireSurface,
    service: &str,
    method: &str,
) -> Option<(&'s Operation, &'s Dispatch)> {
    for operation in surface.operations {
        for d in operation.dispatch {
            if let Dispatch::Service {
                service: s,
                method: m,
                ..
            } = d
            {
                if *s == service && *m == method {
                    return Some((operation, d));
                }
            }
        }
    }
    None
}

/// The binding one of whose declared mount patterns matches this target, if any.
///
/// The query and the fragment are cut inside [`match_target`], for the reason it cuts them: neither
/// is part of the path, and a mount that failed to match because a client appended a query would
/// answer 404 to a well-formed request.
///
/// The captures a pattern yielded are DROPPED here and are not dropped by
/// [`duplex_binding_at`], and the asymmetry is the honest one rather than an omission. This walk
/// answers for a binding whose operations are named by a member of the posted document — the
/// address is the document's, the mount is only where it was posted, and a capture in it would name
/// nothing the operation is addressed by. A session has no such document and no such member: its
/// binding's mounts are the whole of how it is addressed, so what they captured is the only thing a
/// session is ever told about where it was opened.
#[must_use]
pub fn binding_at<'s>(surface: &'s WireSurface, target: &str) -> Option<&'s BindingDecl> {
    surface
        .bindings
        .iter()
        .find(|b| b.mounts.iter().any(|m| match_target(m, target).is_some()))
}

/// The credential bar the DUPLEX rows of one binding declare, or `None` if it declares none.
///
/// Two answers in one return, and the `None` is the load-bearing half: it says this binding is not a
/// session mount at all. A duplex wire asks this before it upgrades anything, and a binding that
/// only carries request/answer rows has to come back `None` rather than come back a bar — otherwise
/// a surface's ordinary envelope endpoint, declared on a binding that happens to be carried by a
/// duplex-capable transport, is a target strangers can open sessions at.
///
/// Where it does answer, it answers with the STRICTEST bar any duplex row on the binding declares,
/// for the reason the document-row reader fails closed: a mount that took the laxest of two
/// declarations would serve the open reading of a binding somebody wrote a credential onto.
#[must_use]
pub fn duplex_bar(surface: &WireSurface, binding: &str) -> Option<Bar> {
    let mut found: Option<Bar> = None;
    for operation in surface.operations {
        for d in operation.dispatch {
            if let Dispatch::Duplex {
                binding: b,
                bar: row,
                ..
            } = d
            {
                if *b == binding {
                    if *row == Bar::Credential {
                        return Some(Bar::Credential);
                    }
                    found = Some(Bar::Open);
                }
            }
        }
    }
    found
}

/// The DUPLEX binding of one transport that a target opens a session at, and its bar.
///
/// The one walk every duplex wire addresses an upgrade with, written here rather than once per
/// wire, and it asks three questions where a wire that asked only the first would be wrong on the
/// other two:
///
/// * the target is one of the binding's declared mounts;
/// * the binding is carried by THIS transport — a surface routinely declares several bindings over
///   several wires at overlapping paths, and a session opened at some other wire's path would be a
///   session nobody declared, served under that binding's bar;
/// * the binding declares a duplex row — see [`duplex_bar`] for why the absence of one is a refusal
///   rather than a default.
///
/// It names no plane, no protocol and no transport: `key` is the caller's own registry key and every
/// string compared is the DECLARER's.
///
/// ## The third value, and why a session needs it where a posted document does not
///
/// The mounts are PATTERNS ([`BindingDecl::mounts`]), so a match can capture, and what it captured
/// comes back here because there is nowhere else it could. A request/answer operation whose target
/// carries an identifier declares a [`Dispatch::Target`] template and the mount reads the captures
/// off that; a session declares no template — after the upgrade this wire has no target at all — so
/// the pattern that admitted the upgrade is the only place the identifier in the published URL was
/// ever written down. A walk that answered only "yes, this binding" would leave a mount holding a
/// session opened at `/v1/realtime/telephony/7f3a` with no way to say which call it was, and the
/// composition above would have to re-parse the path against a second copy of the pattern.
///
/// In DECLARATION ORDER, and the vector is empty for an all-literal pattern — which is every mount
/// declared before patterns existed, so nothing that matched before matches differently now.
#[must_use]
pub fn duplex_binding_at<'s, 't>(
    surface: &'s WireSurface,
    key: &str,
    target: &'t str,
) -> Option<(&'s BindingDecl, Bar, Vec<Capture<'t>>)> {
    surface.bindings.iter().find_map(|b| {
        if b.transport != key {
            return None;
        }
        let captures = b.mounts.iter().find_map(|m| match_target(m, target))?;
        duplex_bar(surface, b.name).map(|bar| (b, bar, captures))
    })
}

/// Find the operation a document member's value addresses on one binding.
#[must_use]
pub fn resolve_document<'s>(
    surface: &'s WireSurface,
    binding: &str,
    name: &str,
) -> Option<(&'s Operation, &'s Dispatch)> {
    for operation in surface.operations {
        for d in operation.dispatch {
            if let Dispatch::Document {
                binding: b,
                name: n,
                ..
            } = d
            {
                if *b == binding && *n == name {
                    return Some((operation, d));
                }
            }
        }
    }
    None
}
