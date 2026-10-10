// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SECRET'S SOURCE STAYS ON THE OPERATOR'S SIDE OF THE REQUEST-TIME HAND-OFF (coordinator ruling
//! 2026-10-07): the one place on a door plane's request path where a secret reference that does
//! not resolve meets a plugin is a member program's `env` (the loader resolves it when it declares
//! the instance's members, at `open` and every `refresh`). A reference that does not resolve makes
//! its registration NO MEMBER: nothing of it reaches the connection table, and the plugin's open
//! naming that member reaches it as the table's FIXED-CLASS refusal (`ConnError::Refused`, its
//! static text), never the source's own words (the variable's name, the reference as written,
//! "environment variable ... is unset"). The source's refusal is the real one: the linked `env`
//! source, the kind's both-ways fixture.
//!
//! The table here holds the connector's contract for member programs (an open naming a member the
//! declaration did not name is refused, `busbar-core-connector`'s
//! `a_redeclaration_kills_a_changed_or_removed_members_program`), so the cell reads what crosses
//! the hand-off and not one connector's internals. Plane-neutral: the plugin is the loader's own
//! test door, its one need the member-program path.

use std::collections::BTreeSet;

use busbar_contract::secret_ref::{SecretRef, SECRET_MODULE_FILE};

use super::*;

/// The words a secret source's own refusal is phrased in, matched without case. The file source's
/// phrase is built from its module name ([`source_in`]): this neutral crate spells no secret
/// plugin's name.
const SOURCE_WORDS: [&str; 3] = ["environment variable", "is unset", "no such file"];

/// What of `secret`'s source `text` carries: its source's words, the reference as written and the
/// variable it names. Empty when the text is clean.
fn source_in(text: &str, secret: &SecretRef) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut needles: Vec<String> = SOURCE_WORDS.iter().map(|w| (*w).to_string()).collect();
    needles.push(format!("secret {SECRET_MODULE_FILE}"));
    needles.push(secret.describe());
    needles.extend(secret.env_var().map(str::to_string));
    needles
        .into_iter()
        .filter(|n| lower.contains(&n.to_ascii_lowercase()))
        .collect()
}

/// A connection table holding the connector's member-program contract: the members each
/// declaration named, and an open naming any other refused (`ConnError::Refused`).
#[derive(Default)]
struct Members {
    slab: ConnSlab<()>,
    /// Every member-program declaration, as it reached the table.
    declared: Mutex<Vec<Vec<(String, busbar_contract::conn::Program)>>>,
}

impl DeclaredConns for Members {
    fn declare(
        &self,
        _: InstanceId,
        _: NeedId,
        _: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        Err(ConnError::Refused)
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
    fn declare_member_programs(
        &self,
        owner: InstanceId,
        need: NeedId,
        _: &ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
    ) -> Result<(), ConnError> {
        self.declared.lock().unwrap().push(programs.to_vec());
        self.slab.declare(owner, need);
        Ok(())
    }
}

impl Conns for Members {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let member = desc.target.split('/').next().unwrap_or_default();
        let named: BTreeSet<String> = self
            .declared
            .lock()
            .unwrap()
            .last()
            .map(|d| d.iter().map(|(name, _)| name.clone()).collect())
            .unwrap_or_default();
        if !named.contains(member) {
            return Err(ConnError::Refused);
        }
        self.slab.insert(caller, need, ())
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(&self, _: InstanceId, _: ConnId, _: u64, _: &mut [u8]) -> Result<Piece, ConnError> {
        Err(ConnError::Closed)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
        Ok(())
    }
}

/// RED (coordinator ruling 2026-10-07): a member program whose `env` reference does not resolve is
/// no member; the open naming it reaches the plugin as the table's fixed-class refusal, and nothing
/// the table was handed or the plugin read carries the reference's source. A member whose `env`
/// resolves is declared and opened beside it (the control), and the source's own refusal names the
/// source (so a clean hand-off withheld it).
#[test]
fn a_member_whose_env_secret_does_not_resolve_reaches_the_plugin_as_a_fixed_class_refusal() {
    // The root installs the linked secret plugins' resolver; this one is the linked `env` source.
    let _ = crate::dispatch::install_member_secrets(env_reference);
    let var = format!("BUSBAR_LOADER_MEMBER_SECRET_SOURCE_{}", std::process::id());
    std::env::remove_var(&var);
    let secret = SecretRef::env(&var);
    let operator = env_reference(&secret).expect_err("the variable is unset");
    assert!(
        !source_in(&operator, &secret).is_empty(),
        "the source's own refusal names it: {operator}"
    );

    let table = std::sync::Arc::new(Members::default());
    let conns: std::sync::Arc<dyn DeclaredConns> = table.clone();
    let p = bind_as(
        Box::leak(Box::new(MEMBER_NEEDS)),
        crate::dispatch::ConnTable::Host(conns),
    )
    .expect("the instance binds");
    let settings: &'static [u8] = Box::leak(
        format!(
            r#"{{"ghost":{{"command":"/usr/bin/ghost","env":{{"TOKEN":{{"env":"{var}"}}}}}},
                "live":{{"command":"/usr/bin/live"}}}}"#
        )
        .into_bytes()
        .into_boxed_slice(),
    );
    assert_eq!(open_with(&p, settings), Outcome::Ready);

    let declared = table.declared.lock().unwrap().clone();
    assert_eq!(declared.len(), 1, "the members were declared once");
    let names: Vec<&str> = declared[0].iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["live"],
        "the member whose env did not resolve is no member"
    );
    let handed = format!("{declared:?}");
    assert!(
        source_in(&handed, &secret).is_empty(),
        "nothing the table was handed carries the source: {handed}"
    );

    let refused = establish(&p, 0, "ghost");
    assert_eq!(
        refused.outcome,
        RawOutcome::of(Outcome::Refused),
        "the open naming it is refused"
    );
    let text = error_text(&refused);
    assert_eq!(
        text,
        ConnError::Refused.text(),
        "the plugin reads the table's fixed-class refusal"
    );
    assert!(
        source_in(&text, &secret).is_empty(),
        "and nothing of the source: {text}"
    );
    assert_eq!(
        establish(&p, 0, "live").outcome,
        RawOutcome::of(Outcome::Ready),
        "the member whose env resolved is opened"
    );
}
