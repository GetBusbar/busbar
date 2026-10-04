//! The masks of [`super`]: every masked form loses its word, and every real hit keeps it.

use super::*;

fn roots(extra: &[&str]) -> BTreeSet<String> {
    let mut r: BTreeSet<String> = STD_ROOTS.iter().map(|s| (*s).to_string()).collect();
    r.extend(extra.iter().map(|s| (*s).to_string()));
    r
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

#[test]
fn a_std_path_is_not_the_stdio_transport() {
    let r = roots(&[]);
    let m = mask_external_paths("a.rs", "let c = std::process::Stdio::piped();\n", &r);
    assert!(!lower(&m).contains("stdio"), "{m}");
    assert_eq!(m.len(), "let c = std::process::Stdio::piped();\n".len());
    let m = mask_external_paths("a.rs", "use std::process::{Command, Stdio};\n", &r);
    assert!(!lower(&m).contains("stdio"), "{m}");
}

#[test]
fn a_name_imported_from_an_external_crate_is_masked_where_the_file_uses_it_bare() {
    let r = roots(&["oauth_as"]);
    let src = "use oauth_as::{ApprovalDecision, RegistrationDecision as Reg};\n\
               fn f(d: ApprovalDecision) { match d { ApprovalDecision::Approve => {} } let _ = Reg::New; }\n";
    let m = mask_external_paths("a.rs", src, &r);
    assert!(!lower(&m).contains("decision"), "{m}");
    let m = mask_external_paths(
        "a.rs",
        "use std::process::Stdio;\nlet c = Stdio::null();\n",
        &r,
    );
    assert!(!lower(&m).contains("stdio"), "{m}");
}

#[test]
fn a_real_plugin_or_local_name_keeps_its_word() {
    let r = roots(&["oauth_as"]);
    for keep in [
        "use busbar_transport_stdio::Run;\n",
        "busbar_plane_mcp::serve();\n",
        "mod stdio;\nstdio::run();\n",
        "use busbar_plane_decisions::Decision;\n",
        "let x = mine::Stdio;\n",
    ] {
        assert_eq!(mask_external_paths("a.rs", keep, &r), keep, "{keep}");
    }
    // A local path is not the standard library's even when the file also imports its `Stdio`.
    let m = mask_external_paths(
        "a.rs",
        "use std::process::Stdio;\nlet x = mine::Stdio;\n",
        &r,
    );
    assert!(m.contains("mine::Stdio"), "{m}");
    // A path behind a `crate::` / local head, and a string literal, are never external.
    assert_eq!(
        mask_external_paths("a.rs", "let k = \"stdio\"; crate::stdio::run();\n", &r),
        "let k = \"stdio\"; crate::stdio::run();\n"
    );
    // Only Rust is read this way.
    let toml = "std::process::Stdio\n";
    assert_eq!(mask_external_paths("a.toml", toml, &r), toml);
}

#[test]
fn only_a_declared_external_dependency_is_a_root() {
    let tree: BTreeSet<&str> = ["busbar-kernel", "store-memory"].into_iter().collect();
    let r = external_roots(
        [
            ("serde-json", "serde-json"),
            ("busbar-transport-tcp", "tcp"),
            ("store-memory", "store-memory"),
            ("busbar-kernel", "busbar-kernel"),
            ("oauth2", "oauth_as"),
        ],
        &tree,
    );
    assert!(r.contains("std") && r.contains("serde_json") && r.contains("oauth_as"));
    assert!(!r.contains("tcp") && !r.contains("store_memory") && !r.contains("busbar_kernel"));
}

#[test]
fn a_kernel_facade_module_is_the_kernel_not_a_sibling_crate() {
    let m = mask_kernel_facade(
        "a.rs",
        "use busbar_kernel::audit;\nbusbar_kernel::egress::Foo::new();\n",
    );
    assert!(
        m.contains("busbar_kernel::xxxxx;") && m.contains("busbar_kernel::xxxxxx::Foo"),
        "{m}"
    );
    let m = mask_kernel_facade("a.rs", "use busbar_kernel::{audit, egress::X, Kernel};\n");
    assert!(m.contains("{xxxxx, xxxxxx::X, Kernel}"), "{m}");
}

#[test]
fn a_real_kernel_sibling_crate_keeps_its_name() {
    for keep in [
        "use busbar_kernel_audit::Sink;\n",
        "busbar_kernel_egress::send();\n",
        "use busbar_kernel::Kernel;\n",
        "use other::busbar_kernel::audit;\n",
    ] {
        assert_eq!(mask_kernel_facade("a.rs", keep), keep, "{keep}");
    }
    assert_eq!(
        mask_kernel_facade("a.md", "busbar_kernel::audit\n"),
        "busbar_kernel::audit\n"
    );
}
