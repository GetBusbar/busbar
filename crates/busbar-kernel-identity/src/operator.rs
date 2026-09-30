// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operator credential.
//!
//! The single operator admin token a deployment is born with: the one credential that is full by
//! definition, and the one presented on two carriers — `Authorization: Bearer` and
//! `X-Admin-Token`. Which module judges it is the auth axis's business: the kernel opens whatever
//! row answers the provider key, over the token's digest, and hands the result here.
//!
//! The provider key and the principal id are frozen configuration text naming a module no crate in
//! the kernel declares. They sit in the composition root's legacy table, and the root hands them in
//! with its linked auth rows as [`OperatorWords`] (ARCHITECT 2026-09-30, KERNEL-AUTH-ZERO Q2;
//! BUSBAR-1.6.0.md:173, "sit in the root legacy table"). The kernel hands the provider on as `op`,
//! so neither this module nor the kernel names an instance.

use busbar_contract::auth::{AuthModule, AuthVerdict};

/// A linked auth row: the key configuration names it by, and the SDK boundary its crate exports
/// (`BUSBAR_COLD_ENTRY`), run through the one image load a dropped-in `kind: auth` plugin takes.
pub type LinkedAuth = (&'static str, AuthBoundary);
/// The SDK boundary a linked auth row is opened through.
pub type AuthBoundary = &'static busbar_contract::abi::cold::ColdEntry;

/// THE OPERATOR CREDENTIAL'S FROZEN WORDS, as the composition root's legacy table spells them: the
/// provider configuration names it by (the `auth.admin_auth:` default, the one `module:` whose
/// definition may carry `token:`, and a reserved hook name) and the principal id it identifies the
/// operator as. Kind-neutral values; which words they are is the root's business.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OperatorWords {
    /// The operator credential's provider key.
    pub provider: &'static str,
    /// The fixed principal id the operator credential identifies the operator as.
    pub principal_id: &'static str,
}

/// The auth rows this build LINKS (the composition root's, or a test binary's) and the operator
/// credential's words the root hands in beside them, installed once before the first resolution;
/// the first install stands.
static LINKED: std::sync::OnceLock<(&[LinkedAuth], OperatorWords)> = std::sync::OnceLock::new();

/// Install this build's linked auth rows and the operator credential's words.
pub fn install_linked(rows: &'static [LinkedAuth], words: OperatorWords) {
    let _ = LINKED.set((rows, words));
}

/// This build's linked auth rows, in registration order.
pub fn linked() -> &'static [LinkedAuth] {
    LINKED.get().map(|l| l.0).unwrap_or_default()
}

/// The operator credential's words, when a root (or a test binary) handed them in.
pub fn words() -> Option<OperatorWords> {
    LINKED.get().map(|l| l.1)
}

/// The names of this build's linked auth rows, in registration order.
pub fn linked_names() -> Vec<&'static str> {
    linked().iter().map(|r| r.0).collect()
}

/// Whether a linked auth row answers the operator credential's provider `op`.
pub fn answered(op: &str) -> bool {
    linked_names().contains(&op)
}

/// A TEST REGISTRY ROW: link `entry` (the SDK boundary of the auth plugin a test binary links for
/// the operator credential), under the provider key of `words`, as the composition root links its
/// row. The first install stands.
pub fn install_row(words: OperatorWords, entry: AuthBoundary) {
    static ROW: std::sync::OnceLock<[LinkedAuth; 1]> = std::sync::OnceLock::new();
    install_linked(ROW.get_or_init(|| [(words.provider, entry)]), words);
}

/// THE OPERATOR CREDENTIAL'S REFUSALS, v1.5.5's text byte for byte with the provider read off the
/// data table: a configured token no linked row answers.
pub fn unanswered_token(op: &str) -> String {
    format!(
        "an {op} token is configured but this binary was built WITHOUT the `auth-{op}` feature — \
         the admin API would be silently disabled. Rebuild with default features or wire an \
         external admin auth module."
    )
}

/// A `token:` on the chain entry backed by `module`, which is not the operator credential's.
pub fn misplaced_token(op: &str, module: &str) -> String {
    format!(
        "auth chain entry '{module}' sets `token:`, which belongs to the built-in `{op}` module \
         only; move it, e.g.:\n\n    admin_auth:\n      - {op}: {{ token: {{ env: \
         BUSBAR_ADMIN_TOKEN }} }}\n"
    )
}

/// A `token:` on the `identity-providers.<name>` definition backed by `module`.
pub fn misplaced_definition_token(op: &str, name: &str, module: &str) -> String {
    format!(
        "identity-providers.{name}: `token:` is the built-in `{op}` operator credential and is \
         meaningless on `module: {module}`"
    )
}

/// `keys` in the data-plane chain with no admin credential able to mint a key.
pub fn no_mint_path(op: &str) -> String {
    format!(
        "auth.chain names the built-in `keys` verifier but no admin credential can mint one — the \
         data plane would reject every request. Configure auth.admin_auth (an `{op}` entry with a \
         `token:`, or an admin module granting `mint`/`full`), or remove `keys` from auth.chain."
    )
}

/// The configured operator token did not resolve (`e`).
pub fn unresolved_token(op: &str, e: &str) -> String {
    format!("auth.admin_auth {op} token did not resolve: {e}")
}

/// The configured operator token resolved to a blank value.
pub fn blank_token(op: &str) -> String {
    format!(
        "auth.admin_auth {op} `token:` resolved to an EMPTY/whitespace-only value. Refusing to start: \
         the digest would be taken over the blank string, so an empty credential would \
         authenticate as the operator. Check the referenced env var / file actually holds the \
         token, or remove the `token:` to disable the admin API deliberately."
    )
}

/// The 1.4.x `governance.admin_token` held a literal value: the migration's TODO.
pub fn literal_token_todo(op: &str) -> String {
    format!(
        "auth.admin_auth[{op}].token: governance.admin_token held a literal value; move it into an \
         env var or file and reference it (token: {{ env: VAR }} or {{ file: /path }})"
    )
}

/// The migration's change line for the 1.4.x `governance.admin_token`.
pub fn migrated_token(op: &str) -> String {
    format!("governance.admin_token -> auth.admin_auth: [ {op}: {{ token: <secret-ref> }} ]")
}

/// The operator credential, as the auth axis answered it.
pub enum OperatorCredential {
    /// No auth row answers the operator credential's provider.
    Unanswered,
    /// A row answers it and no operator token is configured: nothing to judge, so it defers (and a
    /// chain that only defers denies — the admin surface is closed without a token).
    Unset,
    /// The opened module, over the configured token's digest.
    Module(Box<dyn AuthModule>),
}

impl OperatorCredential {
    /// The operator credential over the token digest `digest`: `answered` says whether a row answers
    /// the [`provider`] key, and `open` opens that row over a digest. FAIL-CLOSED: a row that answers
    /// but cannot open is an error, never a module silently dropped.
    pub fn open(
        answered: bool,
        digest: Option<&str>,
        open: impl FnOnce(&str) -> Result<Box<dyn AuthModule>, String>,
    ) -> Result<Self, String> {
        match (answered, digest) {
            (true, Some(digest)) => open(digest).map(Self::Module),
            (true, None) => Ok(Self::Unset),
            (false, _) => Ok(Self::Unanswered),
        }
    }

    /// Judge the two admin carriers. BOTH are put to the module on every call, whatever the first
    /// answered, and the answers fold: either identifying admits, else either refusing refuses, else
    /// the module defers — so "the Bearer matched" is indistinguishable from "the Bearer missed and
    /// the header matched". `None` when no row answers: the caller says so, and defers.
    pub fn judge(&self, bearer: Option<&str>, header: Option<&str>) -> Option<AuthVerdict> {
        let module = match self {
            Self::Unanswered => return None,
            Self::Unset => return Some(AuthVerdict::Pass),
            Self::Module(module) => module,
        };
        Some(
            match (module.authenticate(bearer), module.authenticate(header)) {
                (AuthVerdict::Identify(p), _) | (_, AuthVerdict::Identify(p)) => {
                    AuthVerdict::Identify(p)
                }
                (AuthVerdict::Reject, _) | (_, AuthVerdict::Reject) => AuthVerdict::Reject,
                _ => AuthVerdict::Pass,
            },
        )
    }
}

/// The operator credential on an admin chain: the credential the auth axis answered, and the
/// provider names it answers for. A provider is the operator credential BY ITS MODULE, never by its
/// name: `ops: { module: <operator provider> }` answers here, and a provider that carries the
/// operator provider's own name but is backed by another module does not, so it is that module.
/// It judges as its credential does (it dereferences to the [`OperatorCredential`] the auth axis
/// answered), and adds only which providers it answers for.
pub struct Operator {
    cred: OperatorCredential,
    names: Vec<String>,
}

impl Operator {
    /// The operator credential of the operator provider `op`, answering for `op` referenced bare,
    /// with nothing opened yet.
    pub fn new(op: &str) -> Self {
        Self {
            cred: OperatorCredential::Unanswered,
            names: vec![op.to_string()],
        }
    }

    /// THE ONE JUDGEMENT: whether the provider `name`, whose `identity-providers:` definition names
    /// `module` (`None`: it has no definition), is the operator credential of the operator provider
    /// `op`. By its module; its name counts only when it is `op` referenced bare.
    pub fn backed(op: &str, name: &str, module: Option<&str>) -> bool {
        module.map_or(name == op, |m| m == op)
    }

    /// The operator credential of `op`, opened as [`OperatorCredential::open`] opens it, answering for
    /// every provider [`Self::backed`] names among the effective definitions `defs` (each provider's
    /// name and module) and for `op` referenced bare unless a definition under that name backs it
    /// with another module.
    pub fn open<'a>(
        op: &str,
        defs: impl Iterator<Item = (&'a str, &'a str)>,
        answered: bool,
        digest: Option<String>,
        open: impl FnOnce(&str) -> Result<Box<dyn AuthModule>, String>,
    ) -> Result<Self, String> {
        let defs: Vec<(&str, &str)> = defs.collect();
        let module_of = |name: &str| defs.iter().find(|d| d.0 == name).map(|d| d.1);
        let names = std::iter::once(op)
            .chain(defs.iter().map(|d| d.0))
            .filter(|name| Self::backed(op, name, module_of(name)))
            .map(str::to_string)
            .collect();
        let cred = OperatorCredential::open(answered, digest.as_deref(), open)?;
        Ok(Self { cred, names })
    }

    /// Whether the admin-chain provider `name` is the operator credential.
    pub fn is(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }

    /// Whether a principal `id` that the admin-chain provider `name` identified is the operator: the
    /// provider is the operator credential and `id` is the principal id it mints (`principal_id`).
    pub fn mints(&self, name: Option<&str>, id: &str, principal_id: &str) -> bool {
        name.is_some_and(|n| self.is(n)) && id == principal_id
    }
}

impl std::ops::Deref for Operator {
    type Target = OperatorCredential;
    fn deref(&self) -> &OperatorCredential {
        &self.cred
    }
}

impl std::ops::DerefMut for Operator {
    fn deref_mut(&mut self) -> &mut OperatorCredential {
        &mut self.cred
    }
}
