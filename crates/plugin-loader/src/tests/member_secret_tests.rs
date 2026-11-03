// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::secret_ref::{SecretRef, SECRET_MODULE_FILE};

use super::*;

const SOURCE_WORDS: [&str; 3] = ["environment variable", "is unset", "no such file"];

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

fn env_reference(r: &SecretRef) -> Result<(), String> {
    if r.module != busbar_contract::secret_ref::SECRET_MODULE_ENV {
        return Err(format!("{} does not resolve", r.describe()));
    }
    use busbar_contract::secret::SecretAxis;
    let mut rows = crate::secret_calls::SecretRows::new(
        || {
            std::sync::Arc::new(crate::dispatch::Dispatcher::new(
                crate::dispatch::DispatchConfig::default(),
            ))
        },
        || None,
    );
    rows.link(crate::actual_env_secret::door)?;
    rows.shared(crate::actual_env_secret::NAME)?
        .resolve(&serde_json::to_vec(&r.settings).expect("the reference settings serialize"))
        .map(drop)
        .map_err(|e| e.text)
}

/// A connection table holding the connector's member-program contract: the members each
/// declaration named, an open naming any other refused (`ConnError::Refused`), and an open whose
/// program's `env` reference does not resolve ([`env_reference`]) at its spawn refused the same.
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
        let program = self
            .declared
            .lock()
            .unwrap()
            .last()
            .and_then(|d| d.iter().find(|(name, _)| name == member).cloned())
            .map(|(_, program)| program);
        let Some(program) = program else {
            return Err(ConnError::Refused);
        };

        if program
            .env_refs
            .iter()
            .any(|(_, reference)| env_reference(reference).is_err())
        {
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

#[test]
fn a_member_whose_env_secret_does_not_resolve_reaches_the_plugin_as_a_fixed_class_refusal() {
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
    assert_eq!(names, ["ghost", "live"], "both registrations are members");
    let ghost = &declared[0][0].1;
    assert_eq!(
        ghost.env_refs,
        [("TOKEN".to_string(), secret.clone())],
        "the member's env crosses as the reference, unresolved"
    );
    assert!(ghost.env.is_empty(), "and as no value");
    let handed = format!("{declared:?}");
    let refusal: Vec<&str> = SOURCE_WORDS
        .iter()
        .copied()
        .filter(|w| handed.to_ascii_lowercase().contains(w))
        .collect();
    assert!(
        refusal.is_empty() && !handed.contains(&operator),
        "nothing the table was handed carries the source's refusal: {handed}"
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
        "the member with no reference is opened"
    );
}
