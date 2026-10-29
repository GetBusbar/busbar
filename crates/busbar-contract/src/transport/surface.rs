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

/// Whether an operation's answer is one document or a run of them.
///
/// Load-bearing on both sides. A transport reads it to decide whether the response leaves as a
/// single body or as a stream that stays open, and the loop reads it to decide whether the unit is
/// complete in one frame or holds its direction open. A protocol that got this wrong for one
/// operation would answer an open-ended call with a closed body — the client waits for events on a
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
}

impl Dispatch {
    /// Whether this dispatch demands a credential.
    #[must_use]
    pub fn bar(&self) -> Bar {
        match self {
            Dispatch::Target { bar, .. }
            | Dispatch::Document { bar, .. }
            | Dispatch::Service { bar, .. } => *bar,
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
    /// Where this binding's request documents are posted, for a binding whose operations are named
    /// by a document member ([`Dispatch::Document`]).
    ///
    /// A LIST, not one path, because a mount routinely has more than one accepted spelling and every
    /// one of them has to answer. An HTTP client handed `http://host/mount` as a BASE resolves a
    /// request for `/` against it and sends `/mount/`, so a mount declared only without the separator
    /// leaves the single most likely spelling of its own endpoint answering 404. Declaring the set
    /// is what makes that a data question rather than a route somebody has to remember to add.
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
/// template deep enough to exceed it is one no protocol in the tree writes.
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
