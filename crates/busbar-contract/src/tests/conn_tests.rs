// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const A: InstanceId = InstanceId(1);
const B: InstanceId = InstanceId(2);
const NEED: NeedId = NeedId(0);

thread_local! {
    static INSERT_ADMITTED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

pub(super) fn insert_admitted() {
    let callback = INSERT_ADMITTED.with(|slot| slot.borrow_mut().take());
    if let Some(callback) = callback {
        callback();
    }
}

#[test]
fn forgetting_includes_an_insert_already_admitted_for_the_owner() {
    use std::sync::{Barrier, mpsc};

    let s = Arc::new(slab());
    let original = s.insert(A, NEED, "original").unwrap();
    let other = s.insert(B, NEED, "other owner").unwrap();
    let release = Arc::new(Barrier::new(2));
    let (admitted, admission) = mpsc::channel();
    let inserting = {
        let s = Arc::clone(&s);
        let release = Arc::clone(&release);
        std::thread::spawn(move || {
            INSERT_ADMITTED.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    admitted.send(()).unwrap();
                    release.wait();
                }));
            });
            s.insert(A, NEED, "racing insert")
        })
    };
    admission.recv().unwrap();

    let early = s.declared.try_lock().ok().map(|guard| {
        drop(guard);
        s.forget(A)
    });
    let retiring = early.is_none().then(|| {
        let s = Arc::clone(&s);
        std::thread::spawn(move || s.forget(A))
    });
    release.wait();
    let inserted = inserting.join().unwrap();
    let retired = match early {
        Some(ids) => ids,
        None => retiring.unwrap().join().unwrap(),
    };
    for id in &retired {
        s.remove(A, *id).unwrap();
    }

    if let Ok(id) = inserted {
        let _ = s.remove(A, id);
    }
    assert!(retired.contains(&original));
    let inserted = inserted.expect("the admitted insert completes");
    assert!(
        retired.contains(&inserted),
        "forget must return an admitted connection for the host to close"
    );
    assert_eq!(s.get(A, inserted).unwrap_err(), ConnError::Closed);
    assert_eq!(s.insert(A, NEED, "late"), Err(ConnError::UndeclaredNeed));
    assert_eq!(*s.get(B, other).unwrap().1, "other owner");
}

#[test]
fn rejected_and_removed_states_are_dropped_outside_slab_guards() {
    use std::sync::Weak;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct State {
        slab: Weak<ConnSlab<State>>,
        dropped: Arc<AtomicUsize>,
        unlocked: Arc<AtomicUsize>,
    }

    impl Drop for State {
        fn drop(&mut self) {
            let slab = self.slab.upgrade().unwrap();
            if slab.check_need(A, NEED) == Err(ConnError::UndeclaredNeed)
                && slab.forget(A).is_empty()
            {
                self.unlocked.fetch_add(1, Ordering::SeqCst);
            }
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    let s: Arc<ConnSlab<State>> = Arc::new(ConnSlab::default());
    let dropped = Arc::new(AtomicUsize::new(0));
    let unlocked = Arc::new(AtomicUsize::new(0));
    let state = || State {
        slab: Arc::downgrade(&s),
        dropped: Arc::clone(&dropped),
        unlocked: Arc::clone(&unlocked),
    };
    s.declare(A, NEED);
    let conn = s.insert(A, NEED, state()).unwrap();
    assert_eq!(s.forget(A), vec![conn]);
    drop(s.remove(A, conn).unwrap());
    assert_eq!(s.insert(A, NEED, state()), Err(ConnError::UndeclaredNeed));
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert_eq!(unlocked.load(Ordering::SeqCst), 2);
}

fn slab() -> ConnSlab<&'static str> {
    let s = ConnSlab::default();
    s.declare(A, NEED);
    s.declare(B, NEED);
    s
}

/// The owner reaches its own connection, with the need it opened it for.
#[test]
fn the_owner_reaches_its_connection() {
    let s = slab();
    let conn = s.insert(A, NEED, "a's").unwrap();
    let (need, state) = s.get(A, conn).unwrap();
    assert_eq!((need, *state), (NEED, "a's"));
}

/// RED ARM — a CROSS-INSTANCE id is refused, on every operation, with its own refusal text; the
#[test]
fn another_instances_connection_is_refused() {
    let s = slab();
    let conn = s.insert(A, NEED, "a's").unwrap();
    assert_eq!(s.get(B, conn).unwrap_err(), ConnError::NotOwner);
    assert_eq!(s.remove(B, conn).unwrap_err(), ConnError::NotOwner);
    assert_eq!(
        ConnError::NotOwner.to_string(),
        "the connection belongs to another plugin instance"
    );
    assert!(s.get(A, conn).is_ok(), "the owner's connection stands");
}

/// RED ARM — a CLOSED id is refused, and a later connection that reuses its slot is not reached
#[test]
fn a_closed_connection_is_refused_and_its_slot_reuse_is_not_reached() {
    let s = slab();
    let conn = s.insert(A, NEED, "first").unwrap();
    assert_eq!(*s.remove(A, conn).unwrap(), "first");
    assert_eq!(s.get(A, conn).unwrap_err(), ConnError::Closed);
    assert_eq!(s.remove(A, conn).unwrap_err(), ConnError::Closed);
    let reused = s.insert(A, NEED, "second").unwrap();
    assert_ne!(reused, conn, "the slot is reused under a new generation");
    assert_eq!(s.get(A, conn).unwrap_err(), ConnError::Closed);
    assert_eq!(*s.get(A, reused).unwrap().1, "second");
    assert_eq!(s.get(A, ConnId(0)).unwrap_err(), ConnError::Closed);
    assert_eq!(ConnError::Closed.to_string(), "the connection is closed");
}

/// RED ARM — a need the caller never DECLARED opens nothing, even when another instance declared
#[test]
fn an_undeclared_need_opens_nothing() {
    let s: ConnSlab<()> = ConnSlab::default();
    s.declare(B, NeedId(3));
    assert_eq!(
        s.insert(A, NeedId(3), ()).unwrap_err(),
        ConnError::UndeclaredNeed
    );
    assert_eq!(s.check_need(A, NeedId(3)), Err(ConnError::UndeclaredNeed));
    assert_eq!(s.check_need(B, NeedId(3)), Ok(()));
    assert_eq!(
        ConnError::UndeclaredNeed.to_string(),
        "the plugin did not declare this need"
    );
}

#[test]
fn a_program_is_read_from_its_settings_and_refused_when_it_cannot_be_spawned_as_written() {
    use super::{Program, ProgramRefused};
    let read = |v: serde_json::Value| Program::from_settings(&v, &Default::default());
    assert_eq!(
        read(serde_json::json!({
            "command": "/usr/bin/server",
            "args": ["--serve", "-v"],
            "env": {"TOKEN": "s3cr3t"}
        })),
        Ok(Program {
            command: "/usr/bin/server".into(),
            cwd: None,
            args: vec!["--serve".into(), "-v".into()],
            env: vec![("TOKEN".into(), "s3cr3t".into())],
            env_refs: Vec::new(),
        })
    );
    assert_eq!(
        read(serde_json::json!({"command": "/bin/cat"})),
        Ok(Program {
            command: "/bin/cat".into(),
            cwd: None,
            args: Vec::new(),
            env: Vec::new(),
            env_refs: Vec::new(),
        })
    );
    let refused = [
        (serde_json::json!("/bin/cat"), ProgramRefused::NoCommand),
        (serde_json::json!({"args": []}), ProgramRefused::NoCommand),
        (
            serde_json::json!({"command": "cat"}),
            ProgramRefused::NotAbsolute,
        ),
        (
            serde_json::json!({"command": "/bin/cat", "args": "x"}),
            ProgramRefused::Args,
        ),
        (
            serde_json::json!({"command": "/bin/cat", "args": [1]}),
            ProgramRefused::Args,
        ),
        (
            serde_json::json!({"command": "/bin/cat", "env": ["A"]}),
            ProgramRefused::Env,
        ),
        (
            serde_json::json!({"command": "/bin/cat", "env": {"A": 1}}),
            ProgramRefused::Env,
        ),
        (
            serde_json::json!({"command": "/bin/cat", "shell": true}),
            ProgramRefused::UnknownKey,
        ),
        (
            serde_json::json!({"command": "/bin/c\u{0}at"}),
            ProgramRefused::Nul,
        ),
        (
            serde_json::json!({"command": "/bin/cat", "env": {"A=B": "c"}}),
            ProgramRefused::Nul,
        ),
    ];
    for (value, why) in refused {
        assert_eq!(read(value.clone()), Err(why), "{value}");
    }
}

#[test]
fn a_programs_environment_never_prints() {
    let p = super::Program {
        command: "/usr/bin/server".into(),
        cwd: None,
        args: vec!["--serve".into(), "argument-secret-canary".into()],
        env: vec![("TOKEN".into(), "s3cr3t-value".into())],
        env_refs: Vec::new(),
    };
    let printed = format!("{p:?}");
    assert!(printed.contains("TOKEN") && printed.contains("/usr/bin/server"));
    assert!(!printed.contains("s3cr3t-value"), "{printed}");
    assert!(!printed.contains("argument-secret-canary"), "{printed}");
    assert!(printed.contains("argument_count: 2"), "{printed}");
}

#[test]
fn a_program_working_directory_is_explicit_absolute_and_part_of_its_identity() {
    use super::{Program, ProgramRefused};
    let base = Program::from_settings(
        &serde_json::json!({"command": "/bin/pwd"}),
        &Default::default(),
    )
    .unwrap();
    assert_eq!(base.cwd, None);
    assert_eq!(
        Program::from_settings(
            &serde_json::json!({"command": "/bin/pwd", "cwd": null}),
            &Default::default()
        ),
        Ok(base.clone())
    );
    let at = Program::from_settings(
        &serde_json::json!({"command": "/bin/pwd", "cwd": "/srv"}),
        &Default::default(),
    )
    .unwrap();
    assert_eq!(at.cwd.as_deref(), Some("/srv"));
    assert_ne!(at, base);
    for cwd in [
        serde_json::json!(false),
        serde_json::json!(""),
        serde_json::json!("relative"),
        serde_json::json!(" /srv"),
        serde_json::json!("/srv "),
    ] {
        assert_eq!(
            Program::from_settings(
                &serde_json::json!({"command": "/bin/pwd", "cwd": cwd}),
                &Default::default()
            ),
            Err(ProgramRefused::Cwd)
        );
    }
    assert_eq!(
        Program::from_settings(
            &serde_json::json!({"command": "/bin/pwd", "cwd": "/srv\0bad"}),
            &Default::default()
        ),
        Err(ProgramRefused::Nul)
    );
}

#[test]
fn a_registrations_program_is_its_command_args_and_env_and_nothing_else() {
    use super::{Program, ProgramRefused};
    assert_eq!(
        Program::of_member(
            &serde_json::json!({
                "transport": "pipe",
                "command": "/usr/bin/server",
                "args": ["--serve"],
                "env": {"LEVEL": "debug"},
                "pin": {"mechanism": "unpinned"},
                "tools_allow": ["a"],
                "cwd": "/srv"
            }),
            &Default::default()
        ),
        Some(Ok(Program {
            command: "/usr/bin/server".into(),
            cwd: Some("/srv".into()),
            args: vec!["--serve".into()],
            env: vec![("LEVEL".into(), "debug".into())],
            env_refs: Vec::new(),
        }))
    );
    assert_eq!(
        Program::of_member(
            &serde_json::json!({"url": "https://up.example/rpc", "pin": {}}),
            &Default::default()
        ),
        None,
        "a registration with no command is no member"
    );
    assert_eq!(
        Program::of_member(&serde_json::json!(["/bin/cat"]), &Default::default()),
        None
    );
    assert_eq!(
        Program::of_member(
            &serde_json::json!({"command": "cat", "pin": {}}),
            &Default::default()
        ),
        Some(Err(ProgramRefused::NotAbsolute))
    );
    assert!(crate::section::member_program("settings.*"));
    assert!(!crate::section::member_program("settings.*.url"));
    assert!(crate::section::member_target("settings.*").is_none());
}

/// THE OWNED-SECTION PATH (`owned.<section>.<key>`): a namespace of its own, answered only for a
#[test]
fn an_owned_path_is_its_own_namespace() {
    use crate::section::owned_path;
    assert_eq!(owned_path("owned.agent_push.ca"), Some("agent_push.ca"));
    assert_eq!(owned_path("owned.webhooks"), Some("webhooks"));
    for not in [
        "settings.agent_push.ca",
        "settings.*.client_identity",
        "settings.*",
        "owned.",
        "owned",
        "owned.agent_push.",
        "owned..ca",
        "",
    ] {
        assert_eq!(owned_path(not), None, "{not:?}");
    }
}

/// A program's `env` entry written as a secret REFERENCE is held as the reference
#[test]
fn a_programs_environment_is_held_as_its_declared_reference() {
    use crate::abi::mechanism::door::{REWRITE_SUGAR, REWRITE_SUGAR_ROLE, SUGAR_ROLE_FILL};
    use crate::secret_ref::{SecretRef, Sugars};
    let mut sources = Sugars::default();
    sources
        .declare(
            "fixture-source",
            &[
                (REWRITE_SUGAR, "lookup".into(), "slot".into()),
                (REWRITE_SUGAR_ROLE, "lookup".into(), SUGAR_ROLE_FILL.into()),
            ],
        )
        .unwrap();
    let template = SecretRef::template("Bearer ${SECRET_VAR}", &sources).unwrap();
    let value = serde_json::json!({
        "command": "/usr/bin/server",
        (crate::conn::PROGRAM_ENV_KEY): {
            "PLAIN": "v", "KEY": {"lookup": "SECRET_VAR"}, "T": template,
        }
    });
    assert_eq!(
        Program::from_settings(&value, &Sugars::default()),
        Err(ProgramRefused::Env)
    );
    let p = Program::from_settings(&value, &sources).expect("declared source admits program");
    assert_eq!(p.env, vec![("PLAIN".to_owned(), "v".to_owned())]);
    assert_eq!(
        p.env_refs,
        vec![
            (
                "KEY".into(),
                sources
                    .reference_for_role(SUGAR_ROLE_FILL, "SECRET_VAR")
                    .unwrap()
            ),
            ("T".into(), template),
        ]
    );
    let printed = format!("{p:?}");
    assert!(printed.contains("KEY"), "{printed}");
    assert!(!printed.contains("SECRET_VAR"), "{printed}");
    for bad in [
        serde_json::json!(7),
        serde_json::json!(["x"]),
        serde_json::json!({"nope":1}),
    ] {
        assert_eq!(
            Program::from_settings(
                &serde_json::json!({
                    "command":"/bin/x", (crate::conn::PROGRAM_ENV_KEY): {"K":bad}
                }),
                &sources
            ),
            Err(ProgramRefused::Env)
        );
    }
}

/// A target with a query or fragment and no path still has the origin its auth was bound under.
#[test]
fn origin_of_ends_the_authority_at_query_or_fragment() {
    assert_eq!(origin_of("https://h?x=a/b"), "https://h");
    assert_eq!(origin_of("https://h#f/x"), "https://h");
    assert_eq!(origin_of("https://h:8443/p?q=1"), "https://h:8443");
    assert_eq!(origin_of("https://h"), "https://h");
}

/// A framer default whose name is not an RFC 9110 token, or whose value has a control byte, is
/// refused before it reaches the request head.
#[test]
fn completed_for_refuses_illegal_head_bytes() {
    let head = |name: &[u8], value: &[u8]| HeadDefaults {
        lines: vec![(name.to_vec(), value.to_vec())],
        states_length: false,
    };
    let complete = |h: HeadDefaults| h.completed_for(A, NEED, "https://h", |_| false, 0);
    assert!(complete(head(b"x-ok", b"v\tw")).is_ok());
    assert_eq!(complete(head(b"a\"b", b"v")), Err(ConnError::Refused));
    assert_eq!(complete(head(b"x(y", b"v")), Err(ConnError::Refused));
    assert_eq!(complete(head(b"x\xc3\xa9", b"v")), Err(ConnError::Refused));
    assert_eq!(complete(head(b"x", b"\x01")), Err(ConnError::Refused));
    assert_eq!(complete(head(b"x", b"a\x7fb")), Err(ConnError::Refused));
}

/// A freed slot is reused by the next insert, with its generation advanced so the old id is dead.
#[test]
fn insert_reuses_a_freed_slot_with_a_new_generation() {
    let s = slab();
    let first = s.insert(A, NEED, "one").unwrap();
    let second = s.insert(A, NEED, "two").unwrap();
    s.remove(A, first).unwrap();
    let third = s.insert(A, NEED, "three").unwrap();
    assert_eq!(
        ConnSlab::<&str>::index(third),
        ConnSlab::<&str>::index(first)
    );
    assert_ne!(third, first);
    assert_eq!(s.get(A, first), Err(ConnError::Closed));
    assert_eq!(*s.get(A, third).unwrap().1, "three");
    assert_eq!(*s.get(A, second).unwrap().1, "two");
}
