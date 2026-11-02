// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{ConnIn, ConnOut, DialIn, ShutIn};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::carrier::Carry;
use busbar_core_connector::framer::FramerDoor;

use busbar_core_connector::doors::{refresh_named, row_bind, Dispatched};

use busbar_test_kit::root_door_fixtures::held_down;

fn opened(row: &str, settings: &TransportSettings) -> Arc<Dispatched> {
    let plugin = crate::root::test_plugins::linked_transport(
        held_down::door,
        row_bind(row).expect("the row binds"),
    );
    Arc::new(Dispatched::open(plugin, settings).expect("the carrier opens"))
}

fn dial(door: &Dispatched) -> Outcome {
    let side = door.side().expect("a carrier crosses on a side");
    let (mut i, mut o) = (blank_in::<DialIn>(), blank_out::<ConnOut>());
    door.carry(side.as_ref(), false, Carry::Dial(&mut i, &mut o))
        .outcome
}

fn end(door: &Dispatched) {
    let side = door.side().expect("a carrier crosses on a side");
    let (mut i, mut o) = (blank_in::<ShutIn>(), blank_out::<OutHead>());
    let shut = door.carry(side.as_ref(), false, Carry::Shut(&mut i, &mut o));
    assert_eq!(shut.outcome, Outcome::Ready, "the program's end is taken");
}

fn holds(door: &Dispatched, secs: u64) -> bool {
    let side = door.side().expect("a carrier crosses on a side");
    let mut i = blank_in::<ConnIn>();
    i.conn = secs;
    let mut o = blank_out::<OutHead>();
    door.carry(side.as_ref(), false, Carry::Flush(&mut i, &mut o))
        .outcome
        == Outcome::Ready
}

#[test]
fn an_apply_refreshes_a_live_transport_and_its_next_dial_spawns() {
    let settings = TransportSettings::default();
    let door = opened("row159-apply-clears", &settings);
    assert_eq!(
        dial(&door),
        Outcome::Ready,
        "a fresh member's program spawns"
    );
    end(&door);
    assert_eq!(
        dial(&door),
        Outcome::Failed,
        "a program that ended is held down by its carrier"
    );

    let refused = refresh_named(&settings, |name| name.starts_with("row159-"));
    assert!(
        refused.is_empty(),
        "the carrier took the apply's refresh: {refused:?}"
    );
    assert_eq!(
        dial(&door),
        Outcome::Ready,
        "after the apply the carrier's refresh released the hold, and the next dial spawns"
    );
    assert!(
        holds(&door, settings.request_timeout_secs),
        "the refresh handed it the applied timeout"
    );
}

#[test]
fn a_refused_refresh_keeps_the_prior_settings() {
    let settings = TransportSettings::default();
    let door = opened("row159-refused-keeps", &settings);
    assert!(
        holds(&door, settings.request_timeout_secs),
        "it opened with the deployment's timeout"
    );
    let refusing = TransportSettings {
        request_timeout_secs: held_down::REFUSED_TIMEOUT_SECS,
        ..settings
    };
    let why = door
        .refresh(&refusing)
        .expect_err("the sentinel timeout is refused");
    assert!(
        why.contains("did not refresh"),
        "the refusal says so: {why}"
    );
    assert!(
        holds(&door, settings.request_timeout_secs),
        "the refused refresh left the prior timeout in place"
    );
    assert!(
        !holds(&door, held_down::REFUSED_TIMEOUT_SECS),
        "the refused value was not taken"
    );
    assert_eq!(dial(&door), Outcome::Ready, "the instance keeps serving");
}

#[tokio::test]
async fn a_real_stdio_refresh_changes_the_live_line_bound_and_a_refusal_preserves_it() {
    use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
    use busbar_contract::abi::sdk::door::abi_str;
    use busbar_contract::abi::transport::{
        Destination, IoOut, ReadIn, WriteIn, DEST_PROGRAM, READ_END_OF_FRAME, WRITE_END_OF_FRAME,
    };
    use busbar_core_connector::carrier::Driven;
    use busbar_core_connector::doors::bind_on;
    use busbar_core_connector::hostio::{Admission, HostIo};
    use busbar_core_connector::spawn_env::HeldEnv;

    // Refresh is process-wide by the actual plugin's Statement name. Isolate the process so
    // applying a tiny bound here cannot change another test's live stdio connection.
    const CHILD: &str = "BUSBAR_ROOT_REAL_STDIO_REFRESH_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "root::doors_refresh::a_real_stdio_refresh_changes_the_live_line_bound_and_a_refusal_preserves_it", "--nocapture"])
            .env(CHILD, "1")
            .output().unwrap();
        assert!(
            output.status.success(),
            "real stdio refresh child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    crate::root::connector::install_io(&dispatcher);
    let io = Arc::new(HostIo::new());
    assert!(dispatcher.install_io(io.clone()));
    let mut binding = bind_on(&dispatcher);
    binding.instance = Arc::from("real-stdio-refresh");
    let plugin =
        crate::root::test_plugins::linked_transport(busbar_transport_stdio::door::door, binding);
    let settings = TransportSettings {
        request_body_max_bytes: 4,
        ..TransportSettings::default()
    };
    let door = Dispatched::open_on(plugin, &settings, dispatcher).unwrap();
    let mut side = Driven::of(&door).expect("the actual stdio carrier owns a side");
    let program = busbar_contract::conn::Program::from_settings(&serde_json::json!({
        "command": "/bin/cat",
    }))
    .unwrap();
    io.admit(
        side.ticket(),
        Admission::Spawn(program, HeldEnv::written_only()),
    );
    let destination = Destination {
        kind: DEST_PROGRAM,
        _reserved: 0,
        authority: abi_str(""),
        program: abi_str("/bin/cat"),
        args: std::ptr::null(),
        args_len: 0,
        env: std::ptr::null(),
        env_len: 0,
    };
    let mut input = blank_in::<DialIn>();
    input.dest = &destination;
    let mut output = blank_out::<ConnOut>();
    let called = side
        .cross(&door, Carry::Dial(&mut input, &mut output), None)
        .unwrap();
    assert_eq!(
        called.outcome,
        Outcome::Ready,
        "the actual child spawns: {called:?}"
    );
    let connection = output.conn;
    let (native, failure) = io.settle(side.ticket());
    assert!(
        failure.is_none(),
        "the admitted spawn succeeds: {failure:?}"
    );
    let native = native.expect("the real host owns the child pipes");
    assert!(io.program_id(native).is_some());

    let write = |side: &mut Driven, bytes: &[u8]| {
        let mut input = blank_in::<WriteIn>();
        input.conn = connection;
        input.bytes = bytes.as_ptr();
        input.len = bytes.len();
        input.flags = WRITE_END_OF_FRAME;
        let mut output = blank_out::<IoOut>();
        side.cross(&door, Carry::Write(&mut input, &mut output), None)
            .expect("these bounded lines never fill the real pipe")
            .outcome
    };
    assert_eq!(
        write(&mut side, b"12345"),
        Outcome::Failed,
        "the actual carrier enforces the initial four-byte setting"
    );
    let applied = TransportSettings {
        request_body_max_bytes: 8,
        ..settings
    };
    assert!(
        refresh_named(&applied, |row| row == "stdio").is_empty(),
        "the root refresh registry reaches this actual live carrier"
    );
    assert_eq!(
        write(&mut side, b"12345"),
        Outcome::Ready,
        "the same connection takes its newly applied setting"
    );

    let refusing = TransportSettings {
        request_body_max_bytes: 0,
        ..applied
    };
    let refusal = door
        .refresh(&refusing)
        .expect_err("the actual plugin refuses a zero bound");
    assert!(refusal.contains("did not refresh"), "{refusal}");
    assert_eq!(
        write(&mut side, b"1234567"),
        Outcome::Ready,
        "a refused refresh preserves the prior eight-byte bound"
    );
    assert_eq!(
        write(&mut side, b"123456789"),
        Outcome::Failed,
        "the prior finite bound remains enforced"
    );

    for expected in [b"12345".as_slice(), b"1234567".as_slice()] {
        let mut received = Vec::new();
        loop {
            let mut buffer = [0; 16];
            let mut input = blank_in::<ReadIn>();
            input.conn = connection;
            input.buf = buffer.as_mut_ptr();
            input.cap = buffer.len();
            let mut output = blank_out::<IoOut>();
            let called = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                std::future::poll_fn(|cx| {
                    match side.cross(&door, Carry::Read(&mut input, &mut output), Some(cx)) {
                        Some(called) => std::task::Poll::Ready(called),
                        None => std::task::Poll::Pending,
                    }
                }),
            )
            .await
            .expect("the actual child echoes its accepted line");
            assert_eq!(called.outcome, Outcome::Ready, "{called:?}");
            let count = usize::try_from(output.len).unwrap();
            received.extend_from_slice(&buffer[..count]);
            if output.flags & READ_END_OF_FRAME != 0 {
                break;
            }
        }
        assert_eq!(
            received, expected,
            "only accepted lines reached the real child"
        );
    }
    let mut input = blank_in::<ShutIn>();
    input.conn = connection;
    let mut output = blank_out::<OutHead>();
    assert_eq!(
        side.cross(&door, Carry::Shut(&mut input, &mut output), None)
            .unwrap()
            .outcome,
        Outcome::Ready
    );
    assert!(
        io.program_id(native).is_none(),
        "shut retires the actual child handle"
    );
}
