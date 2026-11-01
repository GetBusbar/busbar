// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE DERIVATION HALF OF THE BUILD-PROVENANCE STAMP, in a file two crate roots share.
//
// `build.rs` `include!`s this file so the stamp is computed by it; `main.rs` mounts it under
// `#[cfg(test)]` so the SAME code is unit-testable. Nothing here reads the environment or the
// filesystem: every function is a pure map from the rustc flags cargo actually applied
// (`CARGO_ENCODED_RUSTFLAGS`, split on `\x1f`) to one stamp field. That is the whole point —
// build.rs's header says the stamp exists to make a build-config mismatch impossible to
// MISDIAGNOSE, so a field that is not a function of what reached the compiler is a field that can
// lie, and the pgo field used to be exactly that (it was `BUSBAR_PGO=1 || -Cprofile-use present`,
// an OR whose left arm no shipping path set and nothing validated).
//
// It carries no `#![...]` inner attributes and no `use`, because `include!` splices it into
// build.rs's crate root verbatim.

/// Whether PROFILE-GUIDED OPTIMIZATION genuinely reached rustc, read off the flags cargo applied.
///
/// THIS IS THE ONLY SOURCE FOR THE `pgo=` FIELD, and it is deliberately not an OR with anything an
/// operator can assert. `scripts/pgo-build.sh` (see its note above the optimized build) stopped
/// exporting `BUSBAR_PGO=1` precisely so this bit is the COMPILER's account of what it was given
/// rather than a build script's account of what it meant to send; honouring the env var here would
/// hand that back, and `BUSBAR_PGO=1 cargo build --release` would produce a binary self-reporting
/// `pgo=true` with no profile data anywhere near it.
///
/// `-Cprofile-use=<path>` is what a PGO build passes. Cargo may deliver it as one element
/// (`-Cprofile-use=…`) or as two (`-C`, `profile-use=…`). Only that exact codegen option counts;
/// a profile-generation path or another argument containing the text does not.
pub(crate) fn pgo_from_flags(flags: &[&str]) -> bool {
    flag_value(flags, "profile-use").is_some()
}

/// The codegen options, preserving the order rustc received them.
fn codegen_options<'a>(flags: &'a [&'a str]) -> impl Iterator<Item = &'a str> {
    let mut flags = flags.iter().copied();
    std::iter::from_fn(move || loop {
        let flag = flags.next()?;
        if flag == "-C" {
            return flags.next();
        }
        if let Some(option) = flag.strip_prefix("-C") {
            return Some(option);
        }
    })
}

/// The value of a `-C<name>=<value>` rustc flag, or `None` when no element carries it. Used for
/// `target-cpu`, `target-feature` and `lto`, each of which cargo exposes only through the flag list.
/// The option is matched by its EXACT name (`-Clto=` is not `-Clinker-plugin-lto=`), in either shape
/// cargo hands it over (`-C<name>=…` as one element, or `-C` then `<name>=…`), and when it is passed
/// more than once the LAST wins, except `target-feature`: rustc combines those options in order.
/// Bare `-Clto` means fat LTO.
pub(crate) fn flag_value(flags: &[&str], name: &str) -> Option<String> {
    let mut value = None;
    for option in codegen_options(flags) {
        let found = match option.split_once('=') {
            Some((key, value)) if key == name => value,
            None if option == "lto" && name == "lto" => "fat",
            _ => continue,
        };
        if name == "target-feature" {
            let combined = value.get_or_insert_with(String::new);
            if !combined.is_empty() && !found.is_empty() {
                combined.push(',');
            }
            combined.push_str(found);
        } else {
            value = Some(found.to_string());
        }
    }
    value
}
