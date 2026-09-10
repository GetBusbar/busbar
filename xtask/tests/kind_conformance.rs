// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHARED BATTERY FOR THE FOUR KINDS WHOSE `busbar-contract` TRAIT HAS NO IMPLEMENTOR —
//! `auth`, `secret`, `hooks`, `export` — AND THE SEVEN CRATES IT IS ASKED OF.
//!
//! One test binary, on the tooling side of the tree, for the reason
//! `tests/unit_conformance.rs`'s header states at length: a shared battery is TOOLING, and tooling
//! depends on the plugins it drives, never the reverse. `auth -> plugin-tooling`,
//! `secret -> plugin-tooling`, `hooks -> plugin-tooling` and `export -> plugin-tooling` are
//! `not-allowed` edges this branch would have INTRODUCED, seven of them, and no `[[dep]]` row may
//! admit one. So the seven crates are UNCHANGED by this landing and the subjects are named in
//! `xtask`'s own `[dev-dependencies]`.
//!
//! The kind names and traits are the only thing each block states; the assertion is one, in
//! `battery/contract_kind.rs`, so the day a kind's first crate is re-based onto its contract trait
//! the line that turns green is the line that was red.

#[path = "battery/contract_kind.rs"]
mod conf;

mod auth_admin_tokens {
    //! Conformance: this crate is a well-formed `auth`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo the kind's name and trait, as every crate of the four kinds whose `busbar-contract`
    //! trait has no implementor.
    //!
    //! # THIS TEST IS RED ON PURPOSE
    //!
    //! `kinds::AuthScheme` is implemented NOWHERE in the workspace except `busbar-contract`'s own
    //! object-safety fixtures; this crate sits on the retiring `busbar_api` ABI. `PLUGIN-TREE.md` §8
    //! prices the re-base at ~250 lines and puts it on track R5. Until it lands, the `auth` kind's
    //! boundaries are policed around a trait nothing implements — and a battery that passed on that
    //! would be reporting conformance to a contract nobody has signed.
    //!
    //! It goes green the day the re-base lands, from this same line, without anybody remembering to
    //! come back and turn it on. That is the ratchet the kind gate itself uses.

    use crate::conf;

    #[test]
    fn the_kinds_contract_trait_has_an_implementor() {
        conf::assert_contract_trait_implemented("auth", "AuthScheme", None);
    }
}

mod auth_static_plugin {
    //! Conformance: this crate is a well-formed `auth`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo the kind's name and trait, as every crate of the four kinds whose `busbar-contract`
    //! trait has no implementor.
    //!
    //! # THIS TEST IS RED ON PURPOSE
    //!
    //! `kinds::AuthScheme` is implemented NOWHERE in the workspace except `busbar-contract`'s own
    //! object-safety fixtures; this crate sits on the retiring `busbar_api` ABI. `PLUGIN-TREE.md` §8
    //! prices the re-base at ~250 lines and puts it on track R5. Until it lands, the `auth` kind's
    //! boundaries are policed around a trait nothing implements — and a battery that passed on that
    //! would be reporting conformance to a contract nobody has signed.

    use crate::conf;

    #[test]
    fn the_kinds_contract_trait_has_an_implementor() {
        conf::assert_contract_trait_implemented("auth", "AuthScheme", None);
    }
}

mod secret_example_plugin {
    //! Conformance: this crate is a well-formed `secret`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo the kind's name and trait, as every crate of the four kinds whose `busbar-contract`
    //! trait has no implementor.
    //!
    //! # THIS TEST IS RED ON PURPOSE
    //!
    //! `kinds::Secret` is implemented NOWHERE in the workspace; this crate sits on the retiring
    //! `busbar_api` ABI. `PLUGIN-TREE.md` §8 prices the re-base at ~150 lines on track R5, together
    //! with folding `SecretRef` into the contract. Until it lands, the `secret` kind's boundaries are
    //! policed around a trait nothing implements.

    use crate::conf;

    #[test]
    fn the_kinds_contract_trait_has_an_implementor() {
        conf::assert_contract_trait_implemented("secret", "Secret", None);
    }
}

mod secret_ref {
    //! Conformance: this crate is a well-formed `secret`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo the kind's name and trait, as every crate of the four kinds whose `busbar-contract`
    //! trait has no implementor.
    //!
    //! # THIS TEST IS RED ON PURPOSE, AND FOR TWO REASONS HERE
    //!
    //! First, `kinds::Secret` is implemented nowhere in the workspace. Second, and this crate is the
    //! sharper case: it is a `SecretRef` TYPE crate with no `Secret` impl at all, classified into the
    //! `secret` kind by a directory glob rather than by a declaration — the exact defect
    //! `PLUGIN-TREE.md` §9 records against "kind by glob, not declaration", whose answer is to fold
    //! `SecretRef` into `busbar-contract` and delete the crate. Until one of those two things happens,
    //! this row is red and says which.

    use crate::conf;

    #[test]
    fn the_kinds_contract_trait_has_an_implementor() {
        conf::assert_contract_trait_implemented("secret", "Secret", None);
    }
}

mod hook_test_plugin {
    //! Conformance: this crate is a well-formed `hooks`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo the kind's name and trait, as every crate of the four kinds whose `busbar-contract`
    //! trait has no implementor.
    //!
    //! # THIS TEST IS RED ON PURPOSE
    //!
    //! `kinds::Hook` is implemented NOWHERE in the workspace except `busbar-contract`'s own
    //! object-safety fixtures; this crate sits on the retiring `busbar_api` ABI. `PLUGIN-TREE.md` §8
    //! prices the re-base at ~200 lines on track R5, with the seats coming from the four-seat table.

    use crate::conf;

    #[test]
    fn the_kinds_contract_trait_has_an_implementor() {
        conf::assert_contract_trait_implemented("hooks", "Hook", None);
    }
}

mod hooks_ranking {
    //! Conformance: this crate is a well-formed `hooks`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo the kind's name and trait, as every crate of the four kinds whose `busbar-contract`
    //! trait has no implementor.
    //!
    //! # THIS TEST IS RED ON PURPOSE
    //!
    //! `kinds::Hook` is implemented nowhere in the workspace; this crate implements `busbar_api::
    //! RoutingPolicy` and is classified `hooks` by its directory name. `PLUGIN-TREE.md` §7 renames it
    //! `busbar-hook-ranking` and §8 re-bases it onto `kinds::Hook` at ~200 lines on track R5.

    use crate::conf;

    #[test]
    fn the_kinds_contract_trait_has_an_implementor() {
        conf::assert_contract_trait_implemented("hooks", "Hook", None);
    }
}

mod export_example_plugin {
    //! Conformance: this crate is a well-formed `export`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo the kind's name and trait, as every crate of the four kinds whose `busbar-contract`
    //! trait has no implementor.
    //!
    //! # THIS TEST IS RED ON PURPOSE
    //!
    //! `kinds::Export` is implemented NOWHERE in the workspace; this crate sits on the retiring
    //! `busbar_api` ABI. `PLUGIN-TREE.md` §8 prices the re-base at ~150 lines on track R5, with
    //! `Anchor` for the retention sink.

    use crate::conf;

    #[test]
    fn the_kinds_contract_trait_has_an_implementor() {
        conf::assert_contract_trait_implemented("export", "Export", None);
    }
}
