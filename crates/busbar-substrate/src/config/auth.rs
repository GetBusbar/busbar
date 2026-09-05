// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `auth:` / `identity-providers:` config SHAPES: the wire structs, the resolved auth block and
//! its chain entries, the role-binding grant, the token-mint policy, and the built-in provider
//! names. Plain data with serde derives and pure accessors — nothing here loads a file, resolves a
//! secret, or touches the running `App`. The resolver that joins chain NAMES to definitions
//! (`resolve_auth`) stays in busbar-core, which re-exports every item here at its historical
//! `config::` path.

use serde::{Deserialize, Serialize};

use busbar_api::SecretRef;

/// One entry in the top-level `identity-providers:` NAMED-DEFINITION map (1.5.3). The map
/// KEY is the provider INSTANCE name — the bare name `auth.chain:`, `auth.admin_auth:` and
/// `role_bindings:` all reference — and this value says which `kind: auth` module backs it, how it is
/// configured, and what admin ceiling it carries.
///
/// ```yaml
/// identity-providers:
///   admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
///   corp-ad:      { module: ad, settings: { server: "ldaps://corp" }, max_admin_scope: read-only }
/// auth:
///   chain:      [keys, corp-ad]     # ← bare NAMES
///   admin_auth: [admin-tokens, corp-ad]
///   role_bindings: { corp-ad: { platform: { admin_scope: full } } }
/// ```
///
/// This REVERSES the 1.5.0 inlining: an IdP that serves BOTH planes used to be defined twice (once in
/// `chain:`, once in `admin_auth:`) with two independent copies of its settings that could silently
/// drift. Now it is defined ONCE and referenced twice.
///
/// The built-in `keys` (data-plane signed-key verifier) and `admin-tokens` (operator credential)
/// are referenced BARE with no definition at all; a definition entry exists only when the provider
/// needs config (e.g. `admin-tokens` carrying its `token:` secret ref).
// `Serialize` is required by the overlay's per-entry MERGE (`config::patch::merge_entry`): an
// overlay entry is a PATCH, so the base entry has to be projected back to JSON in order to be
// patched. The projection is config-internal and round-trips straight back into this same struct;
// it reaches no reader and no HTTP response, which is the distinction the settings-leak lint's
// category (c) turns on.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)] // a typo'd key must fail boot, never silently disable a ceiling.
pub struct IdentityProviderCfg {
    /// The module backing this provider: the built-in `keys` / `admin-tokens`, or a `kind: auth`
    /// plugin name/alias resolved through the validated plugin registry. REQUIRED, non-empty.
    pub module: String,
    /// Ceiling on the ADMIN scope obtainable through THIS PROVIDER, regardless of what
    /// `role_bindings:` grants. The accepted values are exactly `read-only` and `full` — the two
    /// `admin::v1::contract::Scope::parse` knows. Anything else is a HARD BOOT ERROR
    /// ("unknown max_admin_scope '…': expected read-only or full"): `resolve_auth` copies this
    /// value onto the RESOLVED `AuthChainEntry` for every provider named in `auth.chain:` /
    /// `auth.admin_auth:`, and `config_validate`'s chain-entry rule parses every one of those. It is
    /// never a silently-ignored key.
    ///
    /// THERE IS NO `none`. To grant NO admin authority through a provider, grant no `admin_scope`
    /// under that provider's `role_bindings:` — the ceiling caps what a grant can reach, it cannot
    /// express the absence of one. (An earlier version of this comment listed `none`, and every doc
    /// page and example config copied it from here; they told operators to write a config the binary
    /// refuses. The value list and the "absent = most restrictive" prose below now agree.)
    ///
    /// 1.5.3 moved this ONTO the definition: it used to sit on a data-plane CHAIN entry,
    /// which was incoherent — an admin ceiling is a property of the identity source, not of one
    /// plane's reference to it. Absent = the MOST RESTRICTIVE default (`read-only`) for every
    /// provider EXCEPT the built-in `admin-tokens` operator credential, which is `full` by
    /// definition and exempt. `full` from an external IdP is always an explicit opt-in.
    #[serde(default)]
    pub max_admin_scope: Option<String>,
    /// The operator ADMIN credential, for a provider whose `module` is the built-in `admin-tokens`
    /// (a secret reference). Meaningless on any other module (validated).
    #[serde(default)]
    pub token: Option<SecretRef>,
    /// HOSTED-LOGIN parameters (freeze blocker). The 1.5.2 `auth.methods:` block FOLDED into this
    /// definition: `browser_login` is inherently per-provider (a client id/secret belongs to ONE
    /// IdP registration), so a separate parallel map was duplicate structure whose two halves could
    /// disagree. PRESENCE of this block is what puts a button on the hosted login page; a provider
    /// without it is headless-only (still usable via `POST /auth/token`).
    #[serde(default)]
    pub browser_login: Option<BrowserLoginCfg>,
    /// The module's own opaque settings (pushed to the auth plugin verbatim).
    #[serde(default)]
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first. The struct now derives `Serialize`, and that
    // serialization has exactly ONE consumer: the overlay's per-entry merge, which projects the
    // base entry to JSON, patches it, and parses it straight back into this same struct.
    pub settings: serde_json::Map<String, serde_json::Value>,
}

/// The top-level `identity-providers:` map: provider NAME → [`IdentityProviderCfg`]. Insertion-ordered
/// so the hosted-login button order is the operator's config order.
pub type IdentityProviders = indexmap::IndexMap<String, IdentityProviderCfg>;

/// A RESOLVED auth-chain entry: one `auth.chain:` / `auth.admin_auth:` NAME joined to the
/// `identity-providers:` definition it references (or synthesized for a bare built-in that needs no
/// definition). This is an INTERNAL type built by busbar-core's `resolve_auth` — it is never
/// deserialized, because 1.5.3 removed the inline chain-entry form entirely (a chain is now a list of
/// bare NAMES).
#[derive(Debug, Clone, PartialEq)]
pub struct AuthChainEntry {
    /// The PROVIDER NAME (the `identity-providers:` key) — the runtime identity `role_bindings.<name>`
    /// binds and `auth_scope_caps` keys off. For a bare built-in this equals the module name.
    pub name: String,
    /// The module backing this provider (built-in `keys` / `admin-tokens`, or a plugin name/alias).
    pub module: String,
    /// The provider's admin ceiling, from its definition. See [`IdentityProviderCfg::max_admin_scope`].
    pub max_admin_scope: Option<String>,
    /// The `admin-tokens` operator credential, from its definition.
    pub token: Option<SecretRef>,
    /// The module's own opaque settings (pushed to an auth plugin verbatim).
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub settings: serde_json::Map<String, serde_json::Value>,
}

impl AuthChainEntry {
    /// A bare, definition-less built-in entry (`chain: [keys]` / `admin_auth: [admin-tokens]`).
    pub fn bare(module: impl Into<String>) -> Self {
        let module = module.into();
        Self {
            name: module.clone(),
            module,
            max_admin_scope: None,
            token: None,
            settings: serde_json::Map::new(),
        }
    }
}

/// One `auth.role_bindings.<module>.<role>` entry - the operator-owned PURE-AUTH policy granted to
/// a ROLE asserted by that specific module (bindings are NESTED BY MODULE, so `ad.platform`
/// and `oidc.platform` are distinct grants and a module can never ride another module's binding).
/// An unbound role grants NOTHING (fail closed). Limits live on the bound `group`, never here.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RoleBindingCfg {
    /// DATA-PLANE grant: pools this role may target. OMITTED = ALL pools;
    /// an explicit `[]` = NO pools (empty list is the empty set).
    #[serde(default)]
    pub allowed_pools: Option<Vec<String>>,
    /// The `groups:` bucket this role's principals charge through. Absent = no group (unlimited).
    #[serde(default)]
    pub group: Option<String>,
    /// The ADMIN scope this role grants: `read-only` | `full`. Absent = no admin access from this
    /// role. A principal holds the UNION of what its bound roles grant (see `Grants` in the contract
    /// module), ceilinged by the asserting module's `max_admin_scope`.
    #[serde(default)]
    pub admin_scope: Option<String>,
}

/// `role_bindings:` - module name -> role name -> grant.
pub type RoleBindings =
    std::collections::BTreeMap<String, std::collections::BTreeMap<String, RoleBindingCfg>>;

/// A TOKEN BINDING MODE (`auth.policy.binding_modes:` / a mint ceiling's `binding_modes:`), 1.6.0.
/// The lifecycle a minted token is bound to, admin-policied:
/// - `time-bound` — expires at its `exp`, no identity tie (the app/service-token lifecycle).
/// - `user-bound` — records the minting IdP subject for ATTRIBUTION and is short-lived; the client
///   re-exchanges against the IdP to stay live (the honest, buildable form — NOT a per-use IdP
///   introspection floor, which standard OIDC cannot provide).
/// - `both` — strongest: time-bound AND carries the IdP subject.
///
/// 1.6.0 auth grammar: the mode is PARSED, VALIDATED, CARRIED and CONSULTED — a mint whose requested
/// mode falls outside the policy's allowed set is refused at `MintPolicy::check_mint` (`admin/mod.rs`).
/// An omitted `auth.policy.binding_modes` allows every mode, so a deployment that configures none
/// keeps byte-identical existing behavior. `rename_all = "kebab-case"` fixes the wire spelling
/// (`time-bound` / `user-bound` / `both`); an enum (not a bare string) means an unknown mode fails
/// boot rather than sitting inert, and adding a mode later is an additive enum-variant append.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BindingMode {
    /// Expires at `exp`; no identity tie. The app/service-token lifecycle.
    TimeBound,
    /// Records the IdP subject for attribution; short-lived + client re-exchange.
    UserBound,
    /// Time-bound AND carries the IdP subject (strongest).
    Both,
}

impl BindingMode {
    /// The WIRE spelling (kebab-case), matching both the `serde(rename_all)` deserialize and the
    /// `VirtualKey.binding_mode` string a minted key records. The single source of truth a runtime
    /// comparison (a mint request's mode vs a policy's allowed set) goes through.
    pub fn as_str(self) -> &'static str {
        match self {
            BindingMode::TimeBound => "time-bound",
            BindingMode::UserBound => "user-bound",
            BindingMode::Both => "both",
        }
    }
}

/// One per-role MINT CEILING (`auth.policy.mint_ceilings.<role>:`), 1.6.0. The upper bound on what a
/// DELEGATED minter holding that role may ever mint — the config-side DEFINITION of the ceiling whose
/// CORE-SIDE enforcement (`MintPolicy::check_mint`, `admin/mod.rs`) mitigates the compromised-app-admin
/// threat (review H2/H3). All fields optional; an omitted ceiling for a role imposes no additional cap here.
/// `deny_unknown_fields`: a typo'd cap key must fail boot, never silently widen the ceiling.
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct MintCeilingCfg {
    /// The longest TTL this role may mint, a duration string (`"7d"`, `"24h"`, …) parsed by
    /// `parse_duration_secs`. Absent ⇒ no ceiling-specific cap (the block-level `max_ttl` still applies).
    pub max_ttl: Option<String>,
    /// The pools this role may mint tokens against — 3-state, matching `allowed_pools` everywhere:
    /// OMITTED (`None`) = ALL pools; explicit `[]` = NO pools; `[list]` = exactly those. The ceiling
    /// is an upper bound: an enforced mint must request a subset.
    pub allowed_pools: Option<Vec<String>>,
    /// The binding modes this role may mint. Absent ⇒ the block-level `binding_modes` applies.
    pub binding_modes: Option<Vec<BindingMode>>,
}

/// The `auth.policy:` block (1.6.0, ADDITIVE) — operator-authored token-mint POLICY, the config half
/// of the config-vs-store split (policy DECLARES how minting is bounded; the minted tokens themselves
/// are DATA → store). Every field optional: an omitted `auth.policy:` block is `Default` and changes
/// nothing (byte-identical existing behavior). A configured block IS enforced: `self_mint` gates the
/// self-serve path (`auth/self_keys.rs`) and the binding-mode / TTL / pool ceilings are applied at
/// `MintPolicy::check_mint` (`admin/mod.rs`).
/// `deny_unknown_fields`: a typo'd policy key must fail boot, not silently disable a control.
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct AuthPolicyCfg {
    /// May users SELF-SERVE mint (`POST /auth/token`)? `None` ⇒ today's behavior (self-mint available
    /// whenever an IdP is configured), unchanged. `Some(false)` DISABLES the self-serve path — an
    /// authenticated, otherwise-eligible identity is refused 403 (`auth/self_keys.rs`); `Some(true)`
    /// makes the intent explicit. Consulted by the mint path after identity is established.
    pub self_mint: Option<bool>,
    /// The binding modes the deployment permits at mint. `None` ⇒ all modes allowed. An explicit list
    /// narrows what a minter may request; a mint of a mode outside it IS refused at
    /// `MintPolicy::check_mint` (`admin/mod.rs`).
    pub binding_modes: Option<Vec<BindingMode>>,
    /// The DEFAULT TTL applied to a minted token when the request names none, a duration string.
    /// Absent ⇒ the built-in `DEFAULT_KEY_TTL_SECS` path (via `auth.key_ttl`) is unchanged.
    pub default_ttl: Option<String>,
    /// The MAX TTL any minted token may carry, a duration string. Absent ⇒ no policy ceiling (the
    /// admin API's own default applies). When both are set, `default_ttl` must be ≤ `max_ttl`
    /// (enforced at validate, fail boot).
    pub max_ttl: Option<String>,
    /// Per-role mint ceilings (`mint_ceilings.<role>:`) — the delegated-app-admin caps (review H2/H3).
    /// Empty by default.
    #[serde(default)]
    pub mint_ceilings: std::collections::BTreeMap<String, MintCeilingCfg>,
}

/// Per-provider browser-login parameters (`identity-providers.<name>.browser_login:`). PRESENCE of
/// this block is what makes a provider show a button on the hosted login page; a provider WITHOUT it
/// is headless-only (still usable via `POST /auth/token`). Holds the confidential-client secret used by
/// the CORE (never the plugin) during the code→token exchange. `deny_unknown_fields`: a typo here
/// (e.g. `client_secrets:`) must fail boot, not silently disable the button.
// `Serialize` for the same single reason `IdentityProviderCfg` has it: it is a nested field of one,
// so the overlay's per-entry merge projection needs it. Config-internal, never a reader-facing view.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BrowserLoginCfg {
    /// The OAuth/OIDC confidential-client secret, a SECRET REFERENCE. OPTIONAL: only the REDIRECT
    /// (OAuth-family) flow is a confidential client that needs one — a CREDENTIAL method (LDAP/AD-bind)
    /// has none. Enforced per the method's `login_kind` at build (`login_kind == Redirect` ⇒ REQUIRED;
    /// `== Credential` ⇒ must be ABSENT). Injected by the core ONLY into the token-exchange hop's
    /// `client_secret` form field; never serialized back to the plugin.
    #[serde(default)]
    pub client_secret: Option<SecretRef>,
    /// The OAuth client id advertised on the authorize URL. Optional here (an IdP-specific plugin may
    /// carry its own); shown on the login button when present.
    #[serde(default)]
    pub client_id: Option<String>,
}

/// One RESOLVED hosted-login method — the projection of an `identity-providers:` definition that
/// carries a `browser_login:` block (freeze blocker). Built by busbar-core's `resolve_auth`, never
/// deserialized: the config-facing shape is the provider definition itself, and this is just the
/// slice of it the login machinery reads.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthMethodCfg {
    /// The `kind: auth` PLUGIN backing this method — the provider definition's `module:`. Distinct
    /// from the map KEY, which is the provider NAME (two named providers may share one module).
    pub module: String,
    /// Browser-login parameters; `Some` ⇒ this provider renders a button on the hosted login page.
    pub browser_login: Option<BrowserLoginCfg>,
    /// The module's own opaque settings, pushed to the module verbatim (issuer, audience, …).
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub settings: serde_json::Map<String, serde_json::Value>,
}

/// The resolved hosted-login methods — insertion-ordered (operator order = login-page button order),
/// keyed by PROVIDER NAME.
pub type AuthMethods = indexmap::IndexMap<String, AuthMethodCfg>;

/// The WIRE shape of the `auth:` block (1.5.3). `chain:` / `admin_auth:` are lists of bare NAMES
/// referencing the top-level `identity-providers:` map (or a bare built-in) — the inline
/// `- <module>: { settings: … }` entry form is REMOVED: a provider is defined once, by name.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct AuthDeployCfg {
    /// See [`AuthCfg::signing_key`].
    #[serde(default)]
    pub signing_key: Option<SecretRef>,
    /// The DATA-PLANE authentication chain, as ordered PROVIDER NAMES. Empty (the default) is the
    /// open front door. `keys` is the built-in signed-key verifier, referenced bare.
    #[serde(default)]
    pub chain: Vec<String>,
    /// The ADMIN auth chain gating `/api/v1/admin/*`, as ordered PROVIDER NAMES. Default
    /// `[admin-tokens]`. `[]` = OPEN admin (dev only; loud boot warning).
    #[serde(default = "default_admin_auth_names")]
    pub admin_auth: Vec<String>,
    /// Role → policy bindings, NESTED BY PROVIDER NAME (see [`RoleBindingCfg`]).
    #[serde(default)]
    pub role_bindings: RoleBindings,
    /// See [`AuthCfg::key_ttl`].
    #[serde(default)]
    pub key_ttl: Option<String>,
    /// The `auth.policy:` token-mint POLICY block (1.6.0, additive). See [`AuthPolicyCfg`]. Absent ⇒
    /// `Default` (no policy caps), unchanged behavior.
    #[serde(default)]
    pub policy: AuthPolicyCfg,
}

impl Default for AuthDeployCfg {
    /// The all-omitted `auth:` block: open front door (empty data chain) + the default
    /// `[admin-tokens]` admin chain, matching the per-field serde defaults exactly.
    fn default() -> Self {
        Self {
            signing_key: None,
            chain: Vec::new(),
            admin_auth: default_admin_auth_names(),
            role_bindings: RoleBindings::new(),
            key_ttl: None,
            policy: AuthPolicyCfg::default(),
        }
    }
}

/// The RESOLVED `auth:` block — each `chain:`/`admin_auth:` NAME joined to its `identity-providers:`
/// definition (see busbar-core's `resolve_auth`). This is what every runtime consumer reads; it is
/// constructed by `resolve`, never parsed from YAML.
#[derive(Debug, Clone)]
pub struct AuthCfg {
    /// The key-signing key: a SECRET REFERENCE resolving to the ed25519 signing key busbar
    /// mints + verifies virtual-key tokens with. Fleet-shared (every node verifying the same tokens
    /// resolves the same key). REQUIRED when the data-plane chain names the built-in `keys` verifier
    /// (signed-token auth); `config_validate` fails closed if it is missing there. 1.5.1 BREAKING:
    /// busbar NO LONGER auto-generates one when absent (the 1.5.0 generate-and-persist-beside-config
    /// behavior boot-looped a read-only config mount) - generate one with
    /// `busbar --generate-signing-key`. Rotating it revokes every outstanding key.
    pub signing_key: Option<SecretRef>,
    /// The DATA-PLANE authentication CHAIN — resolved provider entries in config order. Empty is the
    /// open front door.
    pub chain: Vec<AuthChainEntry>,
    /// The ADMIN auth chain gating `/api/v1/admin/*` (the parallel of `chain` for the operator
    /// surface). Default `[admin-tokens]`. `[]` = OPEN admin (dev only; loud boot warning).
    pub admin_auth: Vec<AuthChainEntry>,
    /// Role -> policy bindings, NESTED BY PROVIDER NAME (see [`RoleBindingCfg`]).
    pub role_bindings: RoleBindings,
    /// The resolved hosted-login methods — every `identity-providers:` entry, keyed by provider name
    /// (see [`AuthMethods`], freeze blocker). Empty when no providers are defined.
    pub methods: AuthMethods,
    /// Admin-set default lifetime for self-service / minted keys (`auth.key_ttl:`), a duration string
    /// (`"90d"`, `"24h"`, …) parsed by `parse_duration_secs`. Absent ⇒ the built-in
    /// `DEFAULT_KEY_TTL_SECS` (90d).
    pub key_ttl: Option<String>,
    /// The resolved `auth.policy:` token-mint POLICY block (1.6.0, additive). Carried verbatim from
    /// [`AuthDeployCfg::policy`]; `Default` when the block is omitted. Parsed/validated/carried in
    /// this increment; consulted by the mint path in a later, Store-touching increment.
    pub policy: AuthPolicyCfg,
}

impl AuthCfg {
    /// Create a default (open front door, default admin chain) AuthCfg for initialization.
    pub fn default_none() -> Self {
        Self {
            signing_key: None,
            chain: vec![],
            admin_auth: default_admin_auth(),
            role_bindings: RoleBindings::new(),
            methods: AuthMethods::new(),
            key_ttl: None,
            policy: AuthPolicyCfg::default(),
        }
    }

    /// TEST-SUPPORT constructor: the default (open, default-admin) posture with ONLY the data-plane
    /// `chain` overridden — the shape the relocated hook-seam tests need. Kept on the test-support
    /// surface so a plane's tests build the posture through one seam rather than a struct literal.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_chain(chain: Vec<AuthChainEntry>) -> Self {
        Self {
            chain,
            ..Self::default_none()
        }
    }

    /// The `admin-tokens` operator-credential secret reference, if configured.
    pub fn admin_token_ref(&self) -> Option<&SecretRef> {
        self.admin_auth
            .iter()
            .chain(self.chain.iter())
            .find(|e| e.module == ADMIN_TOKENS_MODULE)
            .and_then(|e| e.token.as_ref())
    }

    /// Whether a USABLE ADMIN MINT PATH exists — the STRUCTURAL precondition for putting the `keys`
    /// verifier in `auth.chain` (a busbar-MINTED credential can only be issued through an admin
    /// endpoint, so if nothing can mint one every data-plane request would reject). Checked at
    /// validate/boot, which runs BEFORE secrets resolve, so this is purely structural:
    /// - `admin_auth` is explicitly OPEN (`[]`) → anyone can mint (dev). TRUE — the caller WARNs.
    /// - an `admin-tokens` entry carries a `token:` secret ref → the operator credential can mint.
    /// - an external admin module names `max_admin_scope: full` → an admin IdP can mint (1.5.2 scope
    ///   collapse retired the narrower `mint` ceiling; `full` is now the only mutation grant).
    ///
    /// Does NOT resolve the token or consult `role_bindings` (neither is available here); a ceiling of
    /// `full` is the operator's explicit structural declaration that minting is reachable.
    pub fn usable_mint_path(&self) -> bool {
        if self.admin_auth.is_empty() {
            return true;
        }
        self.admin_auth.iter().any(|e| {
            (e.module == ADMIN_TOKENS_MODULE && e.token.is_some())
                || (e.module != ADMIN_TOKENS_MODULE
                    && matches!(e.max_admin_scope.as_deref(), Some("full")))
        })
    }
}

/// The built-in signed-key verifier module name (`auth.chain: [keys]`).
pub const KEYS_MODULE: &str = "keys";
/// The built-in operator admin-token module name (`auth.admin_auth: [admin-tokens]`).
pub const ADMIN_TOKENS_MODULE: &str = "admin-tokens";

/// The BUILT-IN identity providers, referenced BARE from `auth.chain:`/`auth.admin_auth:` with no
/// `identity-providers:` definition at all. A definition entry for one of these exists
/// only when it needs config — `admin-tokens` carrying its `token:` secret ref is the one real case.
pub const BUILTIN_IDENTITY_PROVIDERS: &[&str] = &[KEYS_MODULE, ADMIN_TOKENS_MODULE];

/// The MOST RESTRICTIVE admin ceiling — the default for a provider whose definition omits
/// `max_admin_scope:`. "Most restrictive" is `read-only`, matching the pre-1.5.3 behavior
/// exactly (the retired chain-entry field defaulted the same way); the built-in `admin-tokens`
/// operator credential is EXEMPT (full by definition), which is why `resolve_auth` applies this
/// only to non-`admin-tokens` providers.
pub const DEFAULT_MAX_ADMIN_SCOPE: &str = "read-only";

/// The serde default for `auth.admin_auth:` - the built-in `admin-tokens` provider, referenced bare
/// (the single operator admin token; byte-identical to the pre-chain behavior).
pub fn default_admin_auth_names() -> Vec<String> {
    vec![ADMIN_TOKENS_MODULE.to_string()]
}

/// The RESOLVED form of [`default_admin_auth_names`].
pub fn default_admin_auth() -> Vec<AuthChainEntry> {
    vec![AuthChainEntry::bare(ADMIN_TOKENS_MODULE)]
}
