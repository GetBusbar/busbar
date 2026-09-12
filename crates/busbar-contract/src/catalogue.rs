// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOGUE READ: what a caller may SEE, and what one named thing IS, read through one face by
//! every plane that publishes a catalogue.
//!
//! A plane that fronts registered upstreams publishes three inventories — the callable things, the
//! prompt templates and the readable resources — and every one of them is scoped to the caller
//! asking. Two planes (mcp's `server/discover` + `prompts/get` + `resources/read`, a2a's agent-card
//! discovery) each hold their OWN registry in their own shape, because what an entry IS differs:
//! mcp's tool carries an approved schema digest, a2a's skill carries a fitness query. What is
//! IDENTICAL between them is the READ a published answer performs — enumerate what this caller can
//! reach, and resolve one address the caller named — and that read is this module.
//!
//! ## The caller is BOUND, not passed
//!
//! Unlike [`crate::tasks::TaskStore`], whose principal is a plain string the store files a row
//! under, a catalogue's scoping input is a whole identity-plus-clock-plus-generation value
//! (`busbar_substrate::catalogue::Caller` on the engine side today): a key that may have expired, a
//! registry generation the ask is judged under, and the clock both are compared against. That value
//! is the ENGINE's, and passing it through this face would drag the engine's own vocabulary across
//! a seam whose entire purpose is that it does not cross.
//!
//! So a [`CatalogueView`] is minted FOR ONE CALLER, by whoever holds the registry, and every method
//! on it answers for that caller and no other. A plane reading through it cannot pair one caller's
//! grant with another's enumeration, because it never names a caller at all — the same guarantee
//! the engine's own `Ctx::caller()` gives by building the value once per request, moved to the only
//! side of the seam that can still hold it.
//!
//! ## Not-found and not-granted are ONE answer
//!
//! [`Resolution::NotFound`] covers "no such address" and "not yours" alike, in every arm and for
//! both address kinds. Two distinguishable answers would let a caller enumerate what is behind a
//! grant it does not hold, one probe at a time. This is the same rule
//! [`crate::tasks::TaskStore::get`] states for an id.
//!
//! ## Ambiguity is an ANSWER, not an absence
//!
//! [`Resolution::Ambiguous`] is the third arm because two approvals this caller holds answering one
//! address is a question the registry genuinely cannot decide: which one the caller meant is the
//! caller's own knowledge. Collapsing it into `NotFound` would report a contended approval as a
//! missing one, and picking a winner would serve one upstream's content under another's name.

/// One row of a caller-scoped inventory: what it is called, and where it lives.
///
/// The inventories this face publishes are COUNTED and ATTRIBUTED, not rendered — a discovery
/// document says how many tools this caller can reach and which servers they sit on, and the full
/// rendering of each entry is the plane's own listing method, which reads the plane's own richer
/// shape. Two fields, because two fields are what every reader of an inventory through this face
/// has so far needed, and a field added here is a field every implementor must fill.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CatalogueEntry {
    /// The entry's wire name, as the plane's own namespacing spells it.
    pub name: String,
    /// The registered server this entry belongs to.
    pub server: String,
}

/// WHAT WAS ASKED FOR — the address a caller named, and which inventory it addresses.
///
/// One `resolve` over a kind-tagged address rather than one method per inventory, because the
/// resolution STEP is the same step in both cases (narrow by the caller's grant, then decide
/// between what is left) and the two differ only in what the answer carries. A second method would
/// be a second place for the grant narrowing to be forgotten.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address<'a> {
    /// A prompt template, by its namespaced name.
    Prompt(&'a str),
    /// A resource, by the URI the caller asked for. A plane whose registry carries both literal
    /// approvals and parameterised ones resolves the literal first — an address approved BY NAME
    /// must not be answered by a template that happens to match it.
    Resource(&'a str),
}

/// WHAT WAS FOUND, matching the [`Address`] arm that asked for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    /// A prompt template, already flattened to its message list — see [`PromptTemplate`].
    Prompt(PromptTemplate),
    /// One resource's content block.
    Resource(ResourceBody),
}

/// THE ANSWER to "which approval did this caller mean by this address".
///
/// Three arms rather than an `Option`; see the module header for why the third is not an absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Exactly one, after the caller's grant narrowed the field.
    One(Found),
    /// No such address, OR the caller holds no grant for it. Deliberately one arm.
    NotFound,
    /// The caller is granted MORE THAN ONE thing answering this address. Carries the contending
    /// approvals, named the way an operator can act on them and SORTED by the implementor, so that
    /// two runs of one ambiguity are never reported two different ways.
    Ambiguous(Vec<String>),
}

/// One resolved prompt template, FLATTENED.
///
/// A registry may hold a prompt in either of two operator-facing forms — one bare template string,
/// or a typed message list — and the difference is a fact about how the operator wrote their
/// config, not about what the caller receives. The implementor collapses the bare form into the
/// one-message list it is equivalent to, so a plane rendering this never carries a second rendering
/// path, which is the second place a rendering rule gets forgotten.
///
/// Nothing here is SANITISED and nothing is SUBSTITUTED: both of those passes read the caller's own
/// arguments, which this face never sees, and both belong to the plane that names the wire this
/// text re-enters. The face carries the operator's text as the registry holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PromptTemplate {
    /// The prompt's wire name, as the plane's own namespacing spells it.
    pub name: String,
    /// The registered server this prompt belongs to.
    pub server: String,
    /// The operator's description, unsanitised. `None` where none was written.
    pub description: Option<String>,
    /// The message list, never empty: a registry holding only a bare template answers one message.
    pub messages: Vec<PromptMessage>,
}

/// One message of a [`PromptTemplate`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PromptMessage {
    /// Who is speaking, in the plane's own wire spelling. Carried opaque and never interpreted, for
    /// the same reason [`crate::tasks::TaskRecord::status`] is.
    pub role: String,
    /// What is said.
    pub content: PromptContent,
}

/// One content block of a [`PromptMessage`].
///
/// The arms are the content kinds an operator can declare, and the split between them is exactly
/// the split a renderer must respect: [`PromptContent::Text`] re-enters a model's instruction
/// stream and is filtered on the way out, while the base64 payloads of the other arms are opaque
/// bytes the client was told the type of, which a text filter would corrupt while protecting
/// nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromptContent {
    /// Plain text — the injectable arm.
    Text {
        /// The operator's text, unsanitised and unsubstituted.
        text: String,
    },
    /// Base64 image data and the type the client was told it is.
    Image {
        /// Base64 payload.
        data: String,
        /// The declared media type. Required: a client cannot render bytes it has not been told the
        /// type of.
        mime_type: String,
    },
    /// Base64 audio data, same rule.
    Audio {
        /// Base64 payload.
        data: String,
        /// The declared media type.
        mime_type: String,
    },
    /// An EMBEDDED resource — content carried inline rather than fetched. Its `uri` is an
    /// IDENTIFIER the client may echo, not a promise that the resource read will serve it.
    Resource {
        /// The identifier the client may echo.
        uri: String,
        /// The declared media type, where one was declared.
        mime_type: Option<String>,
        /// The inline text form.
        text: Option<String>,
        /// The inline base64 form. Mutually exclusive with `text`, refused where the registry is
        /// validated rather than re-checked here.
        blob: Option<String>,
    },
}

impl Default for PromptContent {
    fn default() -> Self {
        PromptContent::Text {
            text: String::new(),
        }
    }
}

/// One resolved resource's content.
///
/// The `uri` is the one to ECHO — the address the CALLER asked for, which for a parameterised
/// approval is the expansion rather than the template: a client correlates content with the URI it
/// sent, and answering with an unexpanded template hands back an identifier naming every expansion
/// at once. Where the registry substitutes parameters into the content, it has already done so;
/// the sanitising pass over the result is the plane's, for the same reason it is on the prompt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceBody {
    /// The address to echo back.
    pub uri: String,
    /// The declared media type, where one was declared.
    pub mime_type: Option<String>,
    /// The text form, already parameter-substituted and NOT yet sanitised.
    pub text: Option<String>,
    /// The base64 form. Where this is present it is the one emitted, and `text` is not.
    pub blob: Option<String>,
}

/// THE SEAM every plane's catalogue methods read a registry through, BOUND TO ONE CALLER.
///
/// See the module header for why the caller is bound at mint rather than passed per call.
pub trait CatalogueView {
    /// Every callable thing this caller can reach.
    fn tools_for(&self) -> Vec<CatalogueEntry>;
    /// Every prompt template this caller can reach.
    fn prompts_for(&self) -> Vec<CatalogueEntry>;
    /// Every resource this caller can reach.
    fn resources_for(&self) -> Vec<CatalogueEntry>;
    /// Whether the REGISTRY ITSELF is empty — a different statement from "this caller can reach
    /// nothing", and one a discovery document must make out loud: a client that cannot tell "you
    /// may see nothing" from "there is nothing" will retry for ever.
    fn is_empty(&self) -> bool;
    /// Resolve one address this caller named. See [`Resolution`].
    ///
    /// The [`Found`] arm ALWAYS matches the [`Address`] arm that asked for it. An implementor that
    /// cannot answer in the asked-for kind answers [`Resolution::NotFound`], which is what a reader
    /// treats a mismatched arm as.
    fn resolve(&self, address: Address<'_>) -> Resolution;
}
