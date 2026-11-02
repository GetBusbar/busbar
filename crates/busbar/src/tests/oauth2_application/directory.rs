// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::io::{Read, Write};

const USER: &[u8] = b"uid=alice,dc=example";

fn element(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if bytes.len() < 128 {
        result.push(u8::try_from(bytes.len()).unwrap());
    } else {
        let length = u16::try_from(bytes.len()).expect("bounded LDAP input");
        result.extend_from_slice(&[0x82]);
        result.extend_from_slice(&length.to_be_bytes());
    }
    result.extend_from_slice(bytes);
    result
}

fn take(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 128 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 2 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0_usize, |total, byte| total * 256 + usize::from(*byte));
        (length, &rest[count..])
    };
    if rest.len() < length {
        return None;
    }
    Some((tag, &rest[..length], &rest[length..]))
}

fn packet(socket: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    let mut header = [0; 2];
    socket.read_exact(&mut header).ok()?;
    if header[0] != 0x30 {
        return None;
    }
    let length = if header[1] < 128 {
        usize::from(header[1])
    } else {
        let count = usize::from(header[1] & 0x7f);
        if count == 0 || count > 2 {
            return None;
        }
        let mut encoded = vec![0; count];
        socket.read_exact(&mut encoded).ok()?;
        encoded
            .iter()
            .fold(0_usize, |total, byte| total * 256 + usize::from(*byte))
    };
    let mut content = vec![0; length];
    socket.read_exact(&mut content).ok()?;
    Some(content)
}

fn message(id: &[u8], tag: u8, body: &[u8]) -> Vec<u8> {
    element(0x30, &[element(0x02, id), element(tag, body)].concat())
}

fn result(code: u8) -> Vec<u8> {
    [
        element(0x0a, &[code]),
        element(0x04, b""),
        element(0x04, b""),
    ]
    .concat()
}

fn conversation(mut socket: std::net::TcpStream, delay: std::time::Duration) {
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut bound = false;
    while let Some(packet) = packet(&mut socket) {
        let Some((0x02, id, request)) = take(&packet) else {
            return;
        };
        let Some((operation, body, _)) = take(request) else {
            return;
        };
        match operation {
            0x60 => {
                let Some((0x02, _, body)) = take(body) else {
                    return;
                };
                let Some((0x04, dn, body)) = take(body) else {
                    return;
                };
                let Some((0x80, password, _)) = take(body) else {
                    return;
                };
                std::thread::sleep(delay);
                bound = dn == USER && password == b"pw";
                let code = if bound { 0 } else { 49 };
                if socket.write_all(&message(id, 0x61, &result(code))).is_err() {
                    return;
                }
            }
            0x63 if bound => {
                let Some((0x04, base, _)) = take(body) else {
                    return;
                };
                assert_eq!(
                    base, USER,
                    "the actual LDAP product reads the bound user's groups"
                );
                let attribute = element(
                    0x30,
                    &[
                        element(0x04, b"memberOf"),
                        element(0x31, &element(0x04, b"CN=members,DC=example")),
                    ]
                    .concat(),
                );
                let entry = [element(0x04, USER), element(0x30, &attribute)].concat();
                let response = [message(id, 0x64, &entry), message(id, 0x65, &result(0))].concat();
                if socket.write_all(&response).is_err() {
                    return;
                }
            }
            0x42 => return,
            _ => panic!("the real LDAP product sent an unexpected operation {operation:#x}"),
        }
    }
}

pub(super) fn settings() -> serde_json::Value {
    static ADDRESS: std::sync::OnceLock<std::net::SocketAddr> = std::sync::OnceLock::new();
    settings_for(&ADDRESS, std::time::Duration::ZERO)
}

pub(super) fn pending_settings() -> serde_json::Value {
    static ADDRESS: std::sync::OnceLock<std::net::SocketAddr> = std::sync::OnceLock::new();
    settings_for(&ADDRESS, std::time::Duration::from_secs(3))
}

fn settings_for(
    address: &'static std::sync::OnceLock<std::net::SocketAddr>,
    delay: std::time::Duration,
) -> serde_json::Value {
    let address = address.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("local LDAP endpoint");
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for socket in listener.incoming() {
                let socket = socket.expect("local LDAP connection");
                std::thread::spawn(move || conversation(socket, delay));
            }
        });
        address
    });
    serde_json::json!({
        "url":format!("ldap://{address}"),
        "bind_dn_template":"uid={username},dc=example",
        "base_dn":"dc=example",
    })
}
