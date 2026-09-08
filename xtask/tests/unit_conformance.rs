// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `unit` KIND'S SHARED CONFORMANCE BATTERY, AND THE FOURTEEN CRATES IT IS ASKED OF.
//!
//! ONE TEST BINARY, ON THE TOOLING SIDE OF THE TREE, AND THAT IS THE WHOLE POINT.
//!
//! The obvious shape for a shared battery — the one `store` already had — is a helper crate that
//! every plugin crate takes as a `[dev-dependencies]` edge and calls from its own
//! `tests/<kind>_conformance.rs`. It is the wrong shape, and the kind graph says so out loud: a
//! `unit -> plugin-tooling` edge is `not-allowed`, fourteen of them are fourteen findings, and no
//! `[[dep]]` row can admit an edge a branch INTRODUCED. The dependency runs the wrong way. A unit
//! crate does not know what a testkit is; the TOOLING knows what a unit is, drives it, and reports.
//!
//! So the battery lives here, in `xtask` — the gate runner, which
//! `kind_isolation::OFF_TREE_MANIFESTS` states in its own words is "a workspace member and not a
//! crate of the product tree: it has no kind, it ships in no artifact, and every rule here is a
//! rule it enforces rather than one it is subject to". Its dev-dependencies are edges of the
//! tooling, not of the tree: no kind edge is created, no `[[cell]]` moves, and the fourteen unit
//! crates are unchanged by this landing — which is the test of whether the direction is right.
//!
//! `[dev-dependencies]`, so `cargo run -p xtask -- gate …` (every gate run, on every push) still
//! builds the runner alone; the fourteen crates are compiled by `cargo test -p xtask` and by
//! nothing else.
//!
//! One binary rather than fourteen: the battery's rulings are asked of every sibling in a single
//! run, so a sibling that stops answering is a named failure in the same output rather than a
//! package somebody forgot to include in a `-p` list.

#[path = "battery/unit.rs"]
mod conf;

mod admission {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here.** The door reads an estimate, a principal and a bucket chain and
    //! is lent the admit token, so the battery's `assert_answers` arm needs a fixture rather than a
    //! literal. `busbar-unit-scope` and `busbar-unit-auth` are the kind's worked examples of the full
    //! battery; this crate runs the declaration half today.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_admission::{AdmissionUnit, InMemoryCells};

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<AdmissionUnit<'static, InMemoryCells>>(StepName::Admit);
    }
}

mod audit {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here.** This unit SERVES its step, so its battery arm is
    //! `assert_total` rather than `assert_answers`, and sealing a record takes a fully assembled
    //! `AuditInputs`. `busbar-unit-scope` and `busbar-unit-auth` are the kind's worked examples of the
    //! full battery; this crate runs the declaration half today.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_audit::AuditChain;

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<AuditChain>(StepName::Audit);
    }
}

mod auth {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! This crate is one of the two that run the battery WHOLE; the other twelve run the declaration
    //! half and name, each in its own block, the fixture their answer half is waiting on.

    use crate::conf;
    use busbar_caps::step::Authenticate;
    use busbar_caps::{KernelSeal, StepName, Unit, UnitToken};
    use busbar_unit_auth::unit::AuthInput;
    use busbar_unit_auth::{Auth, AuthChain, AuthRequest};

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<Auth>(StepName::Authenticate);
    }

    /// Every input of the step is answered — with a decision or a refusal, never a panic, never a
    /// block, never a clock read.
    ///
    /// The clock reading is an INPUT (`AuthRequest::now`), which is the whole reason this unit can be
    /// asked the same question twice and answer it the same way; a unit that called `SystemTime::now`
    /// would fail the determinism arm of the battery here rather than in production.
    #[test]
    fn every_input_is_answered() {
        let seal = KernelSeal::acquire_for_kernel();
        let token = UnitToken::<Authenticate>::mint(&seal);
        for candidate in [None, Some("not-a-credential")] {
            for scheme in [None, Some("bearer")] {
                conf::assert_answers(StepName::Authenticate, || {
                    // A FRESH unit per call, which is what makes the battery's determinism arm mean
                    // something: a unit that carried an answer over from the previous call would agree
                    // with itself for the wrong reason.
                    let mut unit = Auth::new(AuthChain::new(Vec::new(), false));
                    let req = AuthRequest {
                        candidate,
                        scheme,
                        declared_schemes: &["bearer"],
                        expected_aud: None,
                        in_handshake: false,
                        now: 1_700_000_000,
                        new_unit: true,
                    };
                    unit.decide(
                        &token,
                        AuthInput {
                            req: &req,
                            cache: None,
                            keys: None,
                            revocations: None,
                            pending: None,
                        },
                    )
                });
            }
        }
    }
}

mod breaker {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here.** This unit SERVES its step, so its battery arm is
    //! `assert_total` rather than `assert_answers`, and a meaningful call needs a configured pool.
    //! `busbar-unit-scope` and `busbar-unit-auth` are the kind's worked examples of the full battery;
    //! this crate runs the declaration half today.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_breaker::BreakerUnit;

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<BreakerUnit>(StepName::Verify);
    }
}

mod cost {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here.** This unit SERVES its step, so its battery arm is
    //! `assert_total` rather than `assert_answers`, and pricing needs a pinned rate card. It is also
    //! the crate whose answers are MONEY, so the two existing integration tests beside this one
    //! (`hot_path_allocation`, `rate_conversion_agreement`) stay the load-bearing ones and this file
    //! adds the kind's declaration check on top rather than replacing anything.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_cost::unit::CostUnit;

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<CostUnit>(StepName::Admit);
    }
}

mod egress {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here, and it is the one crate where it needs a runtime.** Route is the
    //! single step the loop AWAITS, so this unit's answer is a future and the battery's timing arm
    //! would measure how long it takes to BUILD the future, not to run the walk. `busbar-unit-scope`
    //! and `busbar-unit-auth` are the kind's worked examples of the full battery; this crate runs the
    //! declaration half today.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_egress::EgressUnit;

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<EgressUnit>(StepName::Route);
    }
}

mod egress_auth {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here.** This unit SERVES its step, so its battery arm is
    //! `assert_total` rather than `assert_answers`, and it needs an `EgressAuthToken` and an assembled
    //! envelope. `busbar-unit-scope` and `busbar-unit-auth` are the kind's worked examples of the full
    //! battery; this crate runs the declaration half today.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_egress_auth::unit::EgressAuthUnit;

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<EgressAuthUnit>(StepName::Route);
    }
}

mod ledger {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here.** This unit SERVES its step, so its battery arm is
    //! `assert_total` rather than `assert_answers` — and settling CONSUMES the hold, so the battery's
    //! determinism arm (which calls twice) needs a fresh hold per call, which needs the door. It is
    //! also the crate whose answers are MONEY, so the crate's own settlement tests stay the
    //! load-bearing ones and this file adds the kind's declaration check on top.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_ledger::Ledger;

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<Ledger>(StepName::Audit);
    }
}

mod scope {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! This crate is one of the two that run the battery WHOLE; the other twelve run the declaration
    //! half and name, each in its own block, the fixture their answer half is waiting on.
    //!
    //! This crate is the kind's WORKED EXAMPLE for the answer half: it owns its step and its input is
    //! two plain values, so it runs the whole battery. See the note in `every_input_is_answered`.

    use crate::conf;
    use busbar_caps::step::Approve;
    use busbar_caps::{KernelSeal, StepName, Unit, UnitToken};
    use busbar_unit_scope::unit::{ApproveInput, ScopeUnit};
    use busbar_unit_scope::{Grants, Scope};

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<ScopeUnit>(StepName::Approve);
    }

    /// Every input of the step is answered — with a decision or a refusal, never a panic, never a
    /// block, never a clock read.
    ///
    /// Four inputs: what the caller holds crossed with what the operation needs, both rungs of a
    /// two-rung chain. `Full` over `ReadOnly` proceeds and `ReadOnly` under `Full` refuses, so both
    /// arms of the answer are exercised rather than only the happy one.
    #[test]
    fn every_input_is_answered() {
        let seal = KernelSeal::acquire_for_kernel();
        let token = UnitToken::<Approve>::mint(&seal);
        for held in [
            Grants::default(),
            Grants::of(Scope::ReadOnly),
            Grants::of(Scope::Full),
        ] {
            for needed in [Scope::ReadOnly, Scope::Full] {
                conf::assert_answers(StepName::Approve, || {
                    ScopeUnit.decide(&token, ApproveInput { held, needed })
                });
            }
        }
    }
}

mod transport_key {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here, and it is the one crate where the battery's "no I/O" reading
    //! does not apply.** This unit resolves a secret and writes a journal entry, which is why it runs
    //! at listener provisioning and never on the request path; its `decide` needs a secret source, a
    //! journal and a TLS config sink. `busbar-unit-scope` and `busbar-unit-auth` are the kind's worked
    //! examples of the full battery; this crate runs the declaration half today.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_transport_key::unit::TransportKeyUnit;

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<TransportKeyUnit>(StepName::Verify);
    }
}

mod trust {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here.** `Trust::verify` reads three trait objects (a pool view, a
    //! per-kind fact source, a breaker view) and a `TrustToken`, so the battery's `assert_answers` arm
    //! needs a fixture rather than a literal. `busbar-unit-scope` and `busbar-unit-auth` are the kind's
    //! worked examples of the full battery; this crate runs the declaration half today, and the note is
    //! here rather than in a tracker so the next reader of this file meets it.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_trust::Trust;

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<Trust>(StepName::Verify);
    }
}

mod usage {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here.** `meter` reads four assembled fact structures and a
    //! `UsageToken`, so the battery's `assert_answers` arm needs a fixture rather than a literal.
    //! `busbar-unit-scope` and `busbar-unit-auth` are the kind's worked examples of the full battery;
    //! this crate runs the declaration half today.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_usage::unit::UsageUnit;

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<UsageUnit>(StepName::Meter);
    }
}

mod verbs {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **Why this sibling carries fixtures the others do not.** `Verbs` is generic over its four
    //! integration seams, so naming the type at all takes four concrete parameters. The stubs below are
    //! inhabited-but-unreachable: every method is `unimplemented!()`, because the declaration half of
    //! the battery reads associated items off the TYPE and never calls one. That also makes them an
    //! honest statement — this file proves the shape, not the behaviour.
    //!
    //! **The answer half is OWED here.** This unit SERVES its step (it is a destination at Route), so
    //! its battery arm is `assert_total` rather than `assert_answers`, and executing a verb needs a
    //! live governance binding. `busbar-unit-scope` and `busbar-unit-auth` are the kind's worked
    //! examples of the full battery.

    use crate::conf;
    use busbar_caps::{AdminToken, StepName};
    use busbar_unit_verbs::governance::{Governance, GovernanceError, MintedKey, RotateOutcome};
    use busbar_unit_verbs::idempotency::ReplayEncoder;
    use busbar_unit_verbs::store::{Store, StoreError};
    use busbar_unit_verbs::verb::KernelVerb;
    use busbar_unit_verbs::verbs::{MintedKeyOutcome, NonceSource, Verbs};

    struct NoGovernance;

    impl Governance for NoGovernance {
        fn group_exists(&self, _name: &str) -> bool {
            unimplemented!("conformance reads the type, never calls it")
        }
        fn actual_parent(&self, _name: &str) -> Option<String> {
            unimplemented!("conformance reads the type, never calls it")
        }
        fn provision_group(
            &self,
            _admin: &AdminToken,
            _group: &str,
            _parent: &str,
        ) -> Result<(), GovernanceError> {
            unimplemented!("conformance reads the type, never calls it")
        }
        fn mint_key(
            &self,
            _admin: &AdminToken,
            _group: Option<&str>,
        ) -> Result<MintedKey, GovernanceError> {
            unimplemented!("conformance reads the type, never calls it")
        }
        fn rotate_key(
            &self,
            _admin: &AdminToken,
            _id: &str,
        ) -> Result<RotateOutcome, GovernanceError> {
            unimplemented!("conformance reads the type, never calls it")
        }
        fn execute_legacy(
            &self,
            _verb: KernelVerb,
            _admin: &AdminToken,
            _request: &[u8],
        ) -> Result<Vec<u8>, GovernanceError> {
            unimplemented!("conformance reads the type, never calls it")
        }
        fn execute_new_verb(
            &self,
            _verb: KernelVerb,
            _admin: &AdminToken,
            _request: &[u8],
        ) -> Result<Vec<u8>, GovernanceError> {
            unimplemented!("conformance reads the type, never calls it")
        }
    }

    struct NoStore;

    impl Store for NoStore {
        fn chain_break(&self, _admin: &AdminToken) -> Result<(), StoreError> {
            unimplemented!("conformance reads the type, never calls it")
        }
        fn store_restore(&self, _admin: &AdminToken, _backup_ref: &str) -> Result<(), StoreError> {
            unimplemented!("conformance reads the type, never calls it")
        }
        fn reseal_epoch_floor(&self, _admin: &AdminToken) -> Result<(), StoreError> {
            unimplemented!("conformance reads the type, never calls it")
        }
        fn replay_new_verb(&self, _key: &(String, String)) -> Result<Option<Vec<u8>>, StoreError> {
            unimplemented!("conformance reads the type, never calls it")
        }
        fn commit_new_verb_replay(
            &self,
            _key: &(String, String),
            _response: &[u8],
        ) -> Result<(), StoreError> {
            unimplemented!("conformance reads the type, never calls it")
        }
    }

    struct NoNonce;

    impl NonceSource for NoNonce {
        fn fill(&self, _buf: &mut [u8; 16]) {
            unimplemented!("conformance reads the type, never calls it")
        }
    }

    struct NoEncoder;

    impl ReplayEncoder<MintedKeyOutcome> for NoEncoder {
        fn encode(&self, _value: &MintedKeyOutcome) -> Vec<u8> {
            unimplemented!("conformance reads the type, never calls it")
        }
    }

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<Verbs<NoGovernance, NoStore, NoNonce, NoEncoder>>(
            StepName::Route,
        );
    }
}

mod wal {
    //! Conformance: this crate is a well-formed `unit`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type and step, as every sibling of the kind — so a ruling added to the
    //! battery is asked of all fourteen crates by the same run, instead of being hand-copied fourteen
    //! times and drifting.
    //!
    //! **The answer half is OWED here.** This unit SERVES its step, so its battery arm is
    //! `assert_total` rather than `assert_answers`, and appending needs an open journal over a segment
    //! backend. `busbar-unit-scope` and `busbar-unit-auth` are the kind's worked examples of the full
    //! battery; this crate runs the declaration half today.

    use crate::conf;
    use busbar_caps::StepName;
    use busbar_unit_wal::Journal;

    #[test]
    fn the_kind_has_one_entry_and_it_names_its_own_step() {
        conf::assert_owns_one_step::<Journal>(StepName::Audit);
    }
}
