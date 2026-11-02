// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{ConnIn, ConnOut, DialIn, ShutIn};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::carrier::Carry;

use busbar_core_connector::doors::{refresh_named, Dispatched};

#[tokio::test]
async fn an_apply_refreshes_a_live_transport_and_its_next_dial_spawns() {
    use busbar_contract::abi::sdk::door::abi_str;
    use busbar_contract::abi::transport::{Destination, IoOut, ReadIn, DEST_PROGRAM};
    use busbar_contract::services::HostServices;
    use busbar_core_connector::carrier::Driven;
    use busbar_core_connector::doors::bind_on;
    use busbar_core_connector::hostio::{Admission, HostIo};
    use busbar_core_connector::spawn_env::HeldEnv;

    const CHILD: &str = "BUSBAR_ROOT_REAL_STDIO_SUPERVISOR_REFRESH_CHILD";
    if std::env::var_os(CHILD).is_none() {
        struct OwnedChild(Option<std::process::Child>);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let mut child = OwnedChild(Some(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "root::doors_refresh::an_apply_refreshes_a_live_transport_and_its_next_dial_spawns", "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn().unwrap(),
        ));
        let bound = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
                child
                    .0
                    .take()
                    .unwrap()
                    .wait()
                    .expect("reap the supervisor witness");
                assert!(
                    status.success(),
                    "actual supervisor refresh failed: {status}"
                );
                return;
            }
            if std::time::Instant::now() >= bound {
                drop(child);
                panic!("actual supervisor refresh exceeded its bound");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    let late = crate::root::serve::LateServices::new();
    let kernel = Arc::new(busbar_kernel::host_services::KernelServices::new());
    late.install_kernel(kernel.clone(), kernel as Arc<dyn HostServices>)
        .unwrap();
    let dispatcher = Arc::new(crate::root::dispatch::build(1, &late));
    crate::root::connector::install_io(&dispatcher);
    let io = Arc::new(HostIo::new());
    assert!(dispatcher.install_io(io.clone()));
    let mut binding = bind_on(&dispatcher);
    binding.instance = Arc::from("real-stdio-supervisor-refresh");
    let plugin =
        crate::root::test_plugins::linked_transport(busbar_transport_stdio::door::door, binding);
    let settings = TransportSettings::default();
    let door = Dispatched::open_on(plugin, &settings, dispatcher).unwrap();
    let mut side = Driven::of(&door).expect("the actual carrier owns a side");
    let program = busbar_contract::conn::Program::from_settings(&serde_json::json!({
        "command": "/bin/true"
    }))
    .unwrap();
    let destination = Destination {
        kind: DEST_PROGRAM,
        _reserved: 0,
        authority: abi_str(""),
        program: abi_str("/bin/true"),
        args: std::ptr::null(),
        args_len: 0,
        env: std::ptr::null(),
        env_len: 0,
    };
    let dial = |side: &mut Driven| {
        io.admit(
            side.ticket(),
            Admission::Spawn(program.clone(), HeldEnv::written_only()),
        );
        let mut input = blank_in::<DialIn>();
        input.dest = &destination;
        input.supervision_key = 159;
        let mut output = blank_out::<ConnOut>();
        let called = side
            .cross(&door, Carry::Dial(&mut input, &mut output), None)
            .unwrap();
        let settled = io.settle(side.ticket());
        (called.outcome, output.conn, settled)
    };
    // Five genuine exits stop restart permanently. This avoids racing the first short
    // backoff when checking that a rejected refresh preserves the supervision state.
    for delay in [Some(120), Some(220), Some(420), Some(820), None] {
        let (outcome, connection, (native, failure)) = dial(&mut side);
        assert_eq!(outcome, Outcome::Ready, "a fresh or elapsed member spawns");
        assert!(failure.is_none(), "the real host spawned it: {failure:?}");
        let native = native.expect("a real child handle");
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut buffer = [0; 8];
            let mut input = blank_in::<ReadIn>();
            input.conn = connection;
            input.buf = buffer.as_mut_ptr();
            input.cap = buffer.len();
            let mut output = blank_out::<IoOut>();
            let called = std::future::poll_fn(|cx| {
                match side.cross(&door, Carry::Read(&mut input, &mut output), Some(cx)) {
                    Some(called) => std::task::Poll::Ready(called),
                    None => std::task::Poll::Pending,
                }
            })
            .await;
            assert_eq!(
                called.outcome,
                Outcome::Ready,
                "the actual child reaches EOF"
            );
            assert_eq!(output.len, 0, "/bin/true produces no stdout");
        })
        .await
        .expect("the real program exits within its bound");
        let mut input = blank_in::<ShutIn>();
        input.conn = connection;
        let mut output = blank_out::<OutHead>();
        assert_eq!(
            side.cross(&door, Carry::Shut(&mut input, &mut output), None)
                .unwrap()
                .outcome,
            Outcome::Ready,
            "the ended connection retires"
        );
        assert!(
            io.program_id(native).is_none(),
            "the ended child was reaped"
        );
        if let Some(delay) = delay {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
    }
    let (outcome, _, (native, _)) = dial(&mut side);
    assert_eq!(
        outcome,
        Outcome::Refused,
        "the repeatedly ended member is held down"
    );
    assert!(native.is_none(), "a held member never spawns");
    let refusing = TransportSettings {
        request_body_max_bytes: 0,
        ..settings
    };
    assert!(door
        .refresh(&refusing)
        .unwrap_err()
        .contains("did not refresh"));
    let (outcome, _, (native, _)) = dial(&mut side);
    assert_eq!(
        outcome,
        Outcome::Refused,
        "a refused apply preserves the hold"
    );
    assert!(native.is_none());
    let refused = refresh_named(&settings, |name| name == "stdio");
    assert!(
        refused.is_empty(),
        "the root's named apply is accepted: {refused:?}"
    );
    let (outcome, connection, (native, failure)) = dial(&mut side);
    assert_eq!(
        outcome,
        Outcome::Ready,
        "the accepted apply releases the hold and the next dial spawns"
    );
    assert!(
        failure.is_none(),
        "the actual new spawn succeeds: {failure:?}"
    );
    let native = native.expect("the refreshed member has a real child handle");
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
        "the new child handle also retires"
    );
}

#[tokio::test]
async fn a_refused_refresh_keeps_the_prior_settings() {
    real_stdio_refresh_keeps_settings(
        "root::doors_refresh::a_refused_refresh_keeps_the_prior_settings",
    )
    .await;
}

#[tokio::test]
async fn a_real_stdio_refresh_changes_the_live_line_bound_and_a_refusal_preserves_it() {
    real_stdio_refresh_keeps_settings("root::doors_refresh::a_real_stdio_refresh_changes_the_live_line_bound_and_a_refusal_preserves_it").await;
}

async fn real_stdio_refresh_keeps_settings(test_name: &'static str) {
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
        struct OwnedChild(Option<std::process::Child>);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let mut child = OwnedChild(Some(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .unwrap(),
        ));
        let bound = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match child
                .0
                .as_mut()
                .unwrap()
                .try_wait()
                .expect("poll the owned child")
            {
                Some(_) => {
                    let status = child
                        .0
                        .take()
                        .unwrap()
                        .wait()
                        .expect("reap the finished child");
                    assert!(
                        status.success(),
                        "real stdio refresh child failed: {status}"
                    );
                    return;
                }
                None if std::time::Instant::now() < bound => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                None => {
                    drop(child); // Kill and reap before reporting an unconditional timeout failure.
                    panic!("real stdio refresh child exceeded its 30-second bound");
                }
            }
        }
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

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        // WriteReady accepts a frame into the carrier's queue. Drive its production Flush
        // before expecting the child to have received and echoed those accepted lines.
        let mut flush = blank_in::<ConnIn>();
        flush.conn = connection;
        let mut flushed = blank_out::<OutHead>();
        let called = std::future::poll_fn(|cx| {
            match side.cross(&door, Carry::Flush(&mut flush, &mut flushed), Some(cx)) {
                Some(called) => std::task::Poll::Ready(called),
                None => std::task::Poll::Pending,
            }
        })
        .await;
        assert_eq!(
            called.outcome,
            Outcome::Ready,
            "the actual carrier flushes its accepted lines: {called:?}"
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
                let called = std::future::poll_fn(|cx| {
                    match side.cross(&door, Carry::Read(&mut input, &mut output), Some(cx)) {
                        Some(called) => std::task::Poll::Ready(called),
                        None => std::task::Poll::Pending,
                    }
                })
                .await;
                assert_eq!(called.outcome, Outcome::Ready, "{called:?}");
                let count = usize::try_from(output.len).unwrap();
                assert!(
                    count != 0 || output.flags & READ_END_OF_FRAME != 0,
                    "a Ready read must make progress or terminate its frame"
                );
                received.extend_from_slice(&buffer[..count]);
                assert!(received.len() <= expected.len(), "bounded echo frame");
                if output.flags & READ_END_OF_FRAME != 0 {
                    break;
                }
            }
            assert_eq!(
                received, expected,
                "only accepted lines reached the real child"
            );
        }
    })
    .await
    .expect("the actual child echoes both accepted lines within one overall bound");
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
