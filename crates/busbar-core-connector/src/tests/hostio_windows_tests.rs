// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native Windows coverage of the host ABI: IOCP streams, inherited child handles,
//! half-close, binary backpressure, process exit and owner teardown.

use std::future::{poll_fn, Future};
use std::time::Duration;

use super::*;
use crate::support::worker;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const OWNER: u64 = 77;

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .expect("native I/O must wake and complete")
}

fn program(script: &str) -> Program {
    let system_root = std::env::var("SystemRoot").expect("Windows system root");
    let command =
        std::path::Path::new(&system_root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    Program {
        command: command.to_string_lossy().into_owned(),
        args: vec![
            "-NoLogo".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            script.into(),
        ],
        // The platform dependency is admitted explicitly; the host environment stays private.
        env: [("SystemRoot".into(), system_root)].into_iter().collect(),
        cwd: None,
        env_refs: Vec::new(),
    }
}

fn spawn(io: &HostIo, program: Program, grant: Ticket) -> u64 {
    io.admit_for(
        grant,
        Admission::Spawn(program.clone(), crate::spawn_env::HeldEnv::written_only()),
        Some(OWNER),
    );
    io.spawn(
        OWNER,
        grant,
        &Spawn {
            program: &program.command,
            args: &program.args.iter().map(String::as_str).collect::<Vec<_>>(),
            env: &program
                .env
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect::<Vec<_>>(),
        },
    )
    .expect("spawn the admitted native program")
}

async fn read_all(io: &HostIo, handle: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut buffer = [0_u8; 16_384];
        let n = poll_fn(|cx| io.read(OWNER, handle, &mut buffer, cx.waker()))
            .await
            .unwrap();
        if n == 0 {
            return output;
        }
        output.extend_from_slice(&buffer[..n]);
    }
}

#[test]
fn native_windows_child_half_close_preserves_binary_bytes_and_exit_status() {
    worker().block_on(bounded(async {
        let io = HostIo::new();
        let handle = spawn(
            &io,
            program(
                "[Console]::OpenStandardInput().CopyTo([Console]::OpenStandardOutput()); exit 37",
            ),
            ticket(701),
        );
        let bytes: Vec<u8> = (0..262_144).map(|n| (n % 251) as u8).collect();
        let write = async {
            let mut offset = 0;
            while offset < bytes.len() {
                let n = poll_fn(|cx| io.write(OWNER, handle, &bytes[offset..], cx.waker()))
                    .await
                    .unwrap();
                assert!(n > 0);
                offset += n;
            }
            // A close must flush already accepted overlapped writes and give the child EOF.
            io.shut(OWNER, handle, DIR_WRITE).unwrap();
            assert!(matches!(
                io.write(OWNER, handle, b"late", Waker::noop()),
                Poll::Ready(Err(_))
            ));
        };
        let (_, output) = futures::join!(write, read_all(&io, handle));
        assert_eq!(output, bytes);
        loop {
            if let Some(code) = io.ends(OWNER, handle).unwrap().exit {
                assert_eq!(code, 37);
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        io.close(OWNER, handle).unwrap();
        assert_eq!(io.held(), 0);
    }));
}

#[test]
fn native_windows_child_uses_admitted_environment_and_working_directory() {
    worker().block_on(bounded(async {
        let io = HostIo::new();
        let mut child = program(
            "[Console]::Write([Environment]::CurrentDirectory + '|' + $env:BUSBAR_CHILD_VISIBLE + '|' + $env:PATH)",
        );
        let directory = std::env::temp_dir();
        child.cwd = Some(directory.to_string_lossy().into_owned());
        child.env.push(("BUSBAR_CHILD_VISIBLE".into(), "admitted".into()));
        let handle = spawn(&io, child, ticket(702));
        io.shut(OWNER, handle, DIR_WRITE).unwrap();
        let output = String::from_utf8(read_all(&io, handle).await).unwrap();
        let mut fields = output.split('|');
        let observed = std::path::PathBuf::from(fields.next().unwrap());
        assert_eq!(observed.canonicalize().unwrap(), directory.canonicalize().unwrap());
        assert_eq!(fields.next(), Some("admitted"));
        assert_eq!(fields.next(), Some(""), "PATH must not leak from the host");
        io.close(OWNER, handle).unwrap();
    }));
}

#[test]
fn native_windows_reap_kills_the_child_and_invalidates_its_handle() {
    worker().block_on(bounded(async {
        let io = HostIo::new();
        let handle = spawn(
            &io,
            program("[Threading.Thread]::Sleep(600000)"),
            ticket(703),
        );
        let retained = io.handles.get(handle).unwrap();
        io.reap(OWNER + 1);
        assert_eq!(io.held(), 1);
        io.reap(OWNER);
        assert_eq!(io.held(), 0);
        assert!(io.ends(OWNER, handle).is_err());
        let Kind::Program(pipes) = &retained.kind else {
            panic!("program")
        };
        loop {
            if pipes.child.lock().unwrap().try_wait().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }));
}

#[test]
fn native_windows_listener_accepts_rearms_and_transfers_a_live_stream() {
    worker().block_on(bounded(async {
        let mut listener = HostListener::bind("127.0.0.1:0").unwrap();
        for _ in 0..3 {
            assert!(listener
                .poll_accept(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let mut client = tokio::net::TcpStream::connect(listener.local_addr())
                .await
                .unwrap();
            let (stream, _) = poll_fn(|cx| listener.poll_accept(cx)).await.unwrap();
            let io = HostIo::new();
            let handle = io
                .handles
                .make(
                    OWNER,
                    Kind::Stream {
                        sock: reactor::register(Sock::Tcp(stream)).unwrap(),
                        connecting: AtomicBool::new(false),
                    },
                )
                .unwrap();
            for value in [b'a', b'b', b'c'] {
                let mut byte = [0];
                assert!(io
                    .read(OWNER, handle, &mut byte, Waker::noop())
                    .is_pending());
                client.write_all(&[value]).await.unwrap();
                assert_eq!(
                    poll_fn(|cx| io.read(OWNER, handle, &mut byte, cx.waker()))
                        .await
                        .unwrap(),
                    1
                );
                assert_eq!(byte, [value]);
            }
            let transferred = io.take_stream(handle).unwrap();
            assert_eq!(io.held(), 0);
            let mut transferred = tokio::net::TcpStream::from_std(transferred).unwrap();
            client.write_all(b"transfer").await.unwrap();
            let mut bytes = [0; 8];
            transferred.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"transfer");
        }
    }));
}

#[test]
fn native_windows_refused_connect_wakes_with_an_error() {
    worker().block_on(bounded(async {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        let io = HostIo::new();
        io.admit(ticket(704), Admission::Dial(vec![address.clone()]));
        if let Ok(handle) = io.open(OWNER, ticket(704), &address) {
            assert!(poll_fn(|cx| io.ready(OWNER, handle, DIR_WRITE, cx.waker()))
                .await
                .is_err());
            io.close(OWNER, handle).unwrap();
        }
        assert_eq!(io.held(), 0);
    }));
}

#[test]
fn native_windows_unix_target_is_explicitly_refused() {
    worker().block_on(async {
        let io = HostIo::new();
        let target = "unix:/run/busbar-unavailable.sock";
        io.admit(ticket(705), Admission::Dial(vec![target.into()]));
        assert!(matches!(
            io.open(OWNER, ticket(705), target),
            Err(IoRefusal::Failed(message)) if message.contains("unavailable on Windows")
        ));
        assert_eq!(io.held(), 0);
        assert!(matches!(
            io.settle(ticket(705)),
            (None, Some(OpenFailure::Failed(_)))
        ));
    });
}
