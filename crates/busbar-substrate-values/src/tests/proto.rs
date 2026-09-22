//! Tests for `proto.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

static ROOTED: ProtocolDecl = ProtocolDecl::named("rooted");
static TEST_ONLY: ProtocolDecl = ProtocolDecl::named("test-only");
static ROOT: ProtocolDecl = ProtocolDecl::named("root");

/// `Registry::decl`'s interned-name fast path compares data POINTERS. A pointer alone does not
/// identify a string: a subslice of an interned `&'static str` (e.g. a caller stripping a suffix
/// off an already-resolved name) starts at the SAME address as the string it was sliced from, so
/// comparing pointers without also comparing LENGTHS treats "root" (the first four bytes of
/// "rooted"'s own interned storage) as if it were "rooted" itself. With both "root" and "rooted"
/// declared — "rooted" first, so it is the one the buggy short-circuit hits — resolving the
/// four-byte slice must come back with root's OWN declaration, not rooted's codec/auth/verbs.
#[test]
fn a_prefix_slice_of_an_interned_name_resolves_its_own_declaration() {
    let reg = Registry::new([&ROOTED, &ROOT]);

    // Not a fresh "root" literal: a slice INTO "rooted"'s own interned storage, so it shares
    // rooted's data pointer while being four bytes long instead of six — exactly what a caller
    // gets back from slicing (not reallocating) an already-interned protocol name.
    let prefix: &str = &ROOTED.name[..4];
    assert_eq!(
        prefix, "root",
        "sanity: the slice reads as the string \"root\""
    );
    assert_eq!(
        prefix.as_ptr(),
        ROOTED.name.as_ptr(),
        "sanity: the slice shares rooted's data pointer rather than being a separate allocation"
    );

    let resolved = reg
        .decl(prefix)
        .expect("\"root\" is a declared protocol name and must resolve to SOME declaration");
    assert_eq!(
        resolved.name, "root",
        "a prefix slice of the interned name \"rooted\" resolved to the \"{}\" declaration \
         instead of \"root\"'s own — wrong codec, wrong auth, wrong verbs",
        resolved.name
    );
}

/// The one test in this binary that installs a root: `install_protocols` is once per process.
/// A test-built binary with a real composition root must fold to the same declaration list
/// as the shipped one, with no re-declaration for the boot fold to skip audibly.
#[test]
fn the_test_seam_does_not_redeclare_what_the_root_installed() {
    install_protocols(vec![&ROOTED]);
    register_test_protocol(&ROOTED);
    register_test_protocol(&TEST_ONLY);
    let names: Vec<&str> = test_registered_protocols().iter().map(|d| d.name).collect();
    assert_eq!(
        names,
        ["test-only"],
        "a root-installed name must not enter the test set"
    );
    let folded: Vec<&str> = registry().decls().iter().map(|d| d.name).collect();
    assert_eq!(
        folded,
        ["rooted", "test-only"],
        "installed first, each name once"
    );
}
