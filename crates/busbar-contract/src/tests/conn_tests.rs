// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const A: InstanceId = InstanceId(1);
const B: InstanceId = InstanceId(2);
const NEED: NeedId = NeedId(0);

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
/// owner's connection is untouched by the attempt.
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
/// through it: the id carries its generation.
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
/// the same number.
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
    let read = |v: serde_json::Value| Program::from_settings(&v);
    assert_eq!(
        read(serde_json::json!({
            "command": "/usr/bin/server",
            "args": ["--serve", "-v"],
            "env": {"TOKEN": "s3cr3t"}
        })),
        Ok(Program {
            command: "/usr/bin/server".into(),
            args: vec!["--serve".into(), "-v".into()],
            env: vec![("TOKEN".into(), "s3cr3t".into())],
            env_refs: Vec::new(),
        })
    );
    assert_eq!(
        read(serde_json::json!({"command": "/bin/cat"})),
        Ok(Program {
            command: "/bin/cat".into(),
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
        args: vec!["--serve".into()],
        env: vec![("TOKEN".into(), "s3cr3t-value".into())],
        env_refs: Vec::new(),
    };
    let printed = format!("{p:?}");
    assert!(printed.contains("TOKEN") && printed.contains("/usr/bin/server"));
    assert!(!printed.contains("s3cr3t-value"), "{printed}");
}

/// RED (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)): a member-program need's member is read off its
/// REGISTRATION: `command`, `args` and `env`, every other key of the registration ignored (it is the
/// registration's own, never the program's); a registration naming no `command` is no member; the
/// three keys are judged as a program is.
#[test]
fn a_registrations_program_is_its_command_args_and_env_and_nothing_else() {
    use super::{Program, ProgramRefused};
    assert_eq!(
        Program::of_member(&serde_json::json!({
            "transport": "stdio",
            "command": "/usr/bin/server",
            "args": ["--serve"],
            "env": {"LEVEL": "debug"},
            "pin": {"mechanism": "unpinned"},
            "tools_allow": ["a"],
            "cwd": "/srv"
        })),
        Some(Ok(Program {
            command: "/usr/bin/server".into(),
            args: vec!["--serve".into()],
            env: vec![("LEVEL".into(), "debug".into())],
            env_refs: Vec::new(),
        }))
    );
    assert_eq!(
        Program::of_member(&serde_json::json!({"url": "https://up.example/rpc", "pin": {}})),
        None,
        "a registration with no command is no member"
    );
    assert_eq!(Program::of_member(&serde_json::json!(["/bin/cat"])), None);
    assert_eq!(
        Program::of_member(&serde_json::json!({"command": "cat", "pin": {}})),
        Some(Err(ProgramRefused::NotAbsolute))
    );
    assert!(crate::section::member_program("settings.*"));
    assert!(!crate::section::member_program("settings.*.url"));
    assert!(crate::section::member_target("settings.*").is_none());
}

/// A program's `env` entry written as a secret REFERENCE is held as the reference
/// (`Program::env_refs`), never resolved by the reader: the host resolves it at the spawn. A
/// value that is neither a string nor a reference is refused.
#[test]
fn a_programs_env_refsironment_is_held_as_its_reference() {
    let p = Program::from_settings(&serde_json::json!({
        "command": "/usr/bin/server",
        (crate::conn::PROGRAM_ENV_KEY): {
            "PLAIN": "v",
            "KEY": {(crate::secret_ref::SECRET_MODULE_ENV): "SECRET_VAR"},
            "T": crate::secret_ref::SecretRef::template("Bearer ${SECRET_VAR}")
        }
    }))
    .expect("a program");
    assert_eq!(p.env, vec![("PLAIN".to_owned(), "v".to_owned())]);
    assert_eq!(
        p.env_refs,
        vec![
            (
                "KEY".to_owned(),
                crate::secret_ref::SecretRef::env("SECRET_VAR")
            ),
            (
                "T".to_owned(),
                crate::secret_ref::SecretRef::template("Bearer ${SECRET_VAR}")
            ),
        ]
    );
    let printed = format!("{p:?}");
    assert!(printed.contains("KEY = env:SECRET_VAR"), "{printed}");
    for bad in [
        serde_json::json!(7),
        serde_json::json!(["x"]),
        serde_json::json!({"nope": 1}),
    ] {
        assert_eq!(
            Program::from_settings(&serde_json::json!({
                "command": "/bin/x",
                (crate::conn::PROGRAM_ENV_KEY): {"K": bad}
            })),
            Err(ProgramRefused::Env)
        );
    }
}
