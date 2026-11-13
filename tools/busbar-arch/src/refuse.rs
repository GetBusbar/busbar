//! Refusals. Every refusal names its rule and says why the rule exists.
//!
//! The first line (`architecture: <message>`) is byte-for-byte the message
//! `scripts/architecture/check.py` prints for the same violation, so the
//! differential CI job can compare the two tools until the Python is deleted.

use std::fmt;

/// One refused property: a stable rule id and the exact message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub rule: Rule,
    pub message: String,
}

impl Violation {
    pub fn new(rule: Rule, message: impl Into<String>) -> Self {
        Violation {
            rule,
            message: message.into(),
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Violation {}

pub type Result<T> = std::result::Result<T, Violation>;

macro_rules! rules {
    ($($id:ident = $name:literal : $why:literal;)*) => {
        /// Every rule the tool can refuse on.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Rule { $($id),* }

        impl Rule {
            pub const ALL: &'static [Rule] = &[$(Rule::$id),*];

            pub fn name(self) -> &'static str {
                match self { $(Rule::$id => $name),* }
            }

            pub fn why(self) -> &'static str {
                match self { $(Rule::$id => $why),* }
            }
        }
    };
}

rules! {
    PolicyVersion = "policy-version":
        "ci/architecture.toml must declare version = 1; an unknown policy shape is never guessed at.";
    PolicyShape = "policy-shape":
        "The policy is missing a required table or field, so no classification can be trusted.";
    UnclassifiedRepository = "unclassified-repository":
        "Only repositories the owner classified in ci/architecture.toml can be admitted; a new repository needs a policy entry first.";
    CRequiresSdk = "c-requires-sdk":
        "A C plugin is compiled against the exact pinned SDK header; without that checkout the ABI cannot be checked.";
    UnclassifiedFirstParty = "unclassified-first-party":
        "Every busbar-* or GetBusbar/BusbarInc package must have a role in the policy, or its edges could not be judged.";
    NoncanonicalSource = "noncanonical-source":
        "A first-party package must come from its own canonical repository (github.com name or the forge), never a relabelled source.";
    PathSubstitution = "path-substitution":
        "A first-party package resolved from a path other than its classified manifest would let a different tree impersonate it.";
    MissingResolve = "missing-resolve":
        "Edges are judged on the resolved graph; metadata without `resolve` (for example --no-deps) proves nothing.";
    TestHostShipping = "test-host-shipping":
        "Conformance test hosts are test-only and must never enter a shipping graph.";
    ShippingFeature = "shipping-feature":
        "test-seal / test-support forge credentials for tests; they must never be enabled in a shipping graph.";
    ForbiddenEdge = "forbidden-edge":
        "Crate boundaries: a first-party package may only depend (normal/build, also through external crates) on what the policy allows.";
    SdkSourceMismatch = "sdk-source-mismatch":
        "All core SDK crates must come from one source revision, or two SDKs would be linked.";
    FirstPartySubstitution = "first-party-substitution":
        "[patch]/[replace] of a first-party package would replace the reviewed source; only core's own assembly may point at its own tree.";
    CargoConfigSubstitution = "cargo-config-substitution":
        ".cargo/config can silently replace the checked manifest graph (patch/paths/source).";
    MissingGenerator = "missing-generator":
        "A generated test host must keep its generator script so its native conformance job can rebuild it.";
    MissingManifest = "missing-manifest":
        "Every classified package must exist at its classified manifest path.";
    PackageIdentity = "package-identity":
        "The package at a classified manifest must keep its classified name.";
    UnresolvedWorkspaceDependency = "unresolved-workspace-dependency":
        "A `workspace = true` dependency must exist in the workspace table, or its source cannot be checked.";
    ForbiddenDeclaredEdge = "forbidden-declared-edge":
        "Declarations are checked too (optional, cfg-disabled, build and dev tables), so an inactive edge cannot hide a boundary break.";
    ShippingFeatureDeclaration = "shipping-feature-declaration":
        "A normal or build dependency must not request test-seal / test-support; only dev-dependencies may.";
    DeclaredSourceMismatch = "declared-source-mismatch":
        "A first-party git dependency must name its own canonical repository.";
    MutableRevision = "mutable-revision":
        "First-party git dependencies must pin a full 40-hex revision, never a branch or tag.";
    CrossRepositoryPath = "cross-repository-path":
        "A path dependency may only point at a package of the same repository at its classified manifest.";
    RegistryFirstParty = "registry-first-party":
        "First-party packages are never taken from a registry.";
    PluginTestFeature = "plugin-test-feature":
        "A plugin must not even declare a test-seal / test-support feature; test authority is core's alone.";
    UnclassifiedMember = "unclassified-member":
        "A new workspace member cannot escape the checks by being left out of the policy.";
    BusbarRef = "busbar-ref":
        ".busbar-ref must name the pinned SDK revision and product 1.6.0, matching every manifest and the lock.";
    VectorSdk = "vector-sdk":
        "scripts/ci-product-pins.json must pin the assembled SDK to a full revision.";
    VectorProduct = "vector-product":
        "Each assembled product must be a classified public wrapper, listed once, at a full commit and lock digest.";
    VectorIncomplete = "vector-incomplete":
        "The assembly vector must list every public, non-standalone Rust plugin; none may be silently dropped.";
    CWitnessVector = "c-witness-vector":
        "The C witness row must name the classified public C plugin at the same SDK and the public header.";
    AssemblyMismatch = "assembly-mismatch":
        "Every first-party git revision in manifests and locks must equal the assembly vector, so one product is built.";
    LockAlignment = "lock-alignment":
        "dist/default must resolve each shared core crate exactly as the root lock, so both workspaces build the same core.";
    LockDrift = "lock-drift":
        "The shipping resolution must not drift from the committed Cargo.lock.";
    SourceRoots = "source-roots":
        "The source checks must see real roots: classified plugin roots and every core member's Rust sources.";
    GeneratedSource = "generated-source":
        "Generated sources included by core must come from this build's own output directory.";
    CompilerWitnessInventory = "compiler-witness-inventory":
        "The compiler witnesses (positive and negative SDK examples) cannot be removed or weakened silently.";
    CompilerWitnessDrift = "compiler-witness-drift":
        "The committed trybuild cases must equal the doc-comment witnesses, so `cargo test` proves the intended rustc errors.";
    CRecipe = "c-recipe":
        "The C witness recipe is bounded data (sources, defines, schema); it can never carry compiler arguments or leave its root.";
    CSource = "c-source":
        "The C plugin is checked from its committed bytes and may include only the public ABI header.";
    CExports = "c-exports":
        "A C plugin must export exactly one symbol, busbar_plugin_door.";
    NativePolicy = "native-policy":
        "The native capability table is a closed set; unknown services, fixtures or scripts are never run.";
    ConformanceRoster = "conformance-roster":
        "A required conformance suite cannot disappear or change its command; the roster must equal conformance/ci-coverage.json.";
    Command = "command":
        "A required tool (cargo, cc, nm, git) failed; the check cannot pass without its result.";
    Io = "io":
        "A required input could not be read.";
    Parse = "parse":
        "An input could not be parsed, so it cannot be judged.";
}

#[cfg(test)]
mod tests {
    use super::Rule;

    #[test]
    fn every_rule_is_explained() {
        let mut names = std::collections::BTreeSet::new();
        for rule in Rule::ALL {
            assert!(!rule.why().is_empty());
            assert!(names.insert(rule.name()), "duplicate rule {}", rule.name());
        }
    }
}
