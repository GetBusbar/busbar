// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dtls engine: demux, the ICE-gated bind, the ring handshake, and every refusal.

use super::*;
use std::time::Duration;

fn p(s: &str) -> SocketAddr {
    s.parse().expect("addr")
}

fn creds(ufrag: &str, pwd: &str) -> IceCredentials {
    IceCredentials {
        ufrag: ufrag.into(),
        pwd: pwd.into(),
    }
}

/// A Binding request as a peer sends it to the owner of `to`: USERNAME "to.ufrag:from_ufrag",
/// MESSAGE-INTEGRITY under `key` (the receiver's pwd when honest), then FINGERPRINT-less.
fn check(to: &IceCredentials, from_ufrag: &str, key: &str) -> Vec<u8> {
    let username = format!("{}:{from_ufrag}", to.ufrag).into_bytes();
    let padded = username.len().div_ceil(4) * 4;
    let mut m = vec![0x00, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    m.extend_from_slice(&[7_u8; 12]);
    m.extend_from_slice(&0x0006_u16.to_be_bytes());
    m.extend_from_slice(&u16::try_from(username.len()).unwrap().to_be_bytes());
    m.extend_from_slice(&username);
    m.resize(20 + 4 + padded, 0);
    let covered_len = u16::try_from(m.len() - 20 + 24).unwrap();
    m[2..4].copy_from_slice(&covered_len.to_be_bytes());
    let key = ::ring::hmac::Key::new(::ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_bytes());
    let tag = ::ring::hmac::sign(&key, &m);
    m.extend_from_slice(&0x0008_u16.to_be_bytes());
    m.extend_from_slice(&20_u16.to_be_bytes());
    m.extend_from_slice(tag.as_ref());
    m
}

/// The success response a full ICE agent sends to a probe: same transaction id, MESSAGE-INTEGRITY
/// under `pwd` (the prober's REMOTE password — the answering agent's own).
fn answer(probe: &[u8], pwd: &str) -> Vec<u8> {
    let mut m = vec![0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    m.extend_from_slice(&probe[8..20]);
    let covered_len = u16::try_from(m.len() - 20 + 24).unwrap();
    m[2..4].copy_from_slice(&covered_len.to_be_bytes());
    let key = ::ring::hmac::Key::new(::ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, pwd.as_bytes());
    let tag = ::ring::hmac::sign(&key, &m);
    m.extend_from_slice(&0x0008_u16.to_be_bytes());
    m.extend_from_slice(&20_u16.to_be_bytes());
    m.extend_from_slice(tag.as_ref());
    m
}

fn is_probe(d: &[u8]) -> bool {
    d.len() >= 20 && d[0..2] == [0x00, 0x01]
}

struct Pair {
    c: Association,
    s: Association,
    c_path: SocketAddr,
    s_path: SocketAddr,
    c_up: Vec<Up>,
    s_up: Vec<Up>,
    /// Answer each side's probes as a full ICE agent would.
    answer_probes: bool,
    now: Instant,
}

const C_ICE: (&str, &str) = ("cfrag", "client-password-0123456789");
const S_ICE: (&str, &str) = ("sfrag", "server-password-0123456789");

fn pair(tamper_server_view_of_client: bool) -> Pair {
    let c_cert = Arc::new(SessionCert::mint().unwrap());
    let s_cert = Arc::new(SessionCert::mint().unwrap());
    let mut c_fp = c_cert.fingerprint();
    if tamper_server_view_of_client {
        c_fp[0] ^= 1;
    }
    let (c_ice, s_ice) = (creds(C_ICE.0, C_ICE.1), creds(S_ICE.0, S_ICE.1));
    let c = Association::new(
        c_cert.clone(),
        Role::Client,
        &c_ice,
        &s_ice,
        s_cert.fingerprint(),
    );
    let s = Association::new(s_cert, Role::Server, &s_ice, &c_ice, c_fp);
    Pair {
        c,
        s,
        c_path: p("203.0.113.9:50000"),
        s_path: p("198.51.100.1:3478"),
        c_up: vec![],
        s_up: vec![],
        answer_probes: true,
        now: Instant::now(),
    }
}

impl Pair {
    /// Each side hears an honest check from the other and binds; the probes are answered by pump.
    fn checked_and_bound(&mut self) {
        let to_s = check(&creds(S_ICE.0, S_ICE.1), C_ICE.0, S_ICE.1);
        let to_c = check(&creds(C_ICE.0, C_ICE.1), S_ICE.0, C_ICE.1);
        assert_eq!(self.s.ingest(self.c_path, &to_s, self.now), Verdict::Raw);
        assert_eq!(self.c.ingest(self.s_path, &to_c, self.now), Verdict::Raw);
        assert_eq!(
            self.s.bind_path(self.c_path, self.now),
            Ok(Bind::WhenProven)
        );
        assert_eq!(
            self.c.bind_path(self.s_path, self.now),
            Ok(Bind::WhenProven)
        );
    }

    fn pump(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.now += Duration::from_millis(10);
            self.c.handle_timeout(self.now);
            self.s.handle_timeout(self.now);
            while let Some((to, d)) = self.c.poll_wire() {
                assert_eq!(to, self.s_path);
                if is_probe(&d) {
                    if self.answer_probes {
                        let a = answer(&d, S_ICE.1);
                        self.c.ingest(self.s_path, &a, self.now);
                    }
                } else {
                    self.s.ingest(self.c_path, &d, self.now);
                }
            }
            while let Some((to, d)) = self.s.poll_wire() {
                if is_probe(&d) {
                    if self.answer_probes && to == self.c_path {
                        let a = answer(&d, C_ICE.1);
                        self.s.ingest(to, &a, self.now);
                    }
                } else if to == self.c_path {
                    self.c.ingest(self.s_path, &d, self.now);
                }
            }
            while let Some(u) = self.c.poll_up() {
                self.c_up.push(u);
            }
            while let Some(u) = self.s.poll_up() {
                self.s_up.push(u);
            }
        }
    }
}

fn keyed(ups: &[Up]) -> Option<&SrtpKeying> {
    ups.iter().find_map(|u| match u {
        Up::Keyed(k) => Some(k),
        _ => None,
    })
}

fn connected(ups: &[Up]) -> bool {
    ups.iter().any(|u| matches!(u, Up::Connected))
}

#[test]
fn rfc7983_first_byte_classes() {
    for (b, class) in [
        (0, Class::Stun),
        (3, Class::Stun),
        (16, Class::Drop),
        (19, Class::Drop),
        (20, Class::Dtls),
        (63, Class::Dtls),
        (64, Class::Drop),
        (79, Class::Drop),
        (127, Class::Drop),
        (128, Class::Media),
        (191, Class::Media),
        (192, Class::Drop),
    ] {
        assert_eq!(classify(&[b, 0, 0]), class, "first byte {b}");
    }
    assert_eq!(classify(&[]), Class::Drop);
}

#[test]
fn handshake_on_ring_exports_one_gcm_keying_and_carries_plaintext_both_ways() {
    let mut t = pair(false);
    t.checked_and_bound();
    t.pump(50);
    assert!(
        connected(&t.c_up) && connected(&t.s_up),
        "both ends connected"
    );
    let (ck, sk) = (keyed(&t.c_up).unwrap(), keyed(&t.s_up).unwrap());
    assert_eq!(ck.profile, sk.profile);
    assert!(matches!(
        ck.profile,
        SrtpProfile::AeadAes128Gcm | SrtpProfile::AeadAes256Gcm
    ));
    assert_eq!(ck.material(), sk.material(), "one exporter, both ends");
    assert!(!ck.material().is_empty());

    t.c.seal(b"sctp from the client").unwrap();
    t.s.seal(b"sctp from the server").unwrap();
    t.pump(3);
    assert!(t
        .s_up
        .iter()
        .any(|u| matches!(u, Up::Plaintext(d) if d == b"sctp from the client")));
    assert!(t
        .c_up
        .iter()
        .any(|u| matches!(u, Up::Plaintext(d) if d == b"sctp from the server")));
}

#[test]
fn red_a_peer_certificate_not_matching_its_sdp_fingerprint_exports_nothing() {
    let mut t = pair(true);
    t.checked_and_bound();
    t.pump(50);
    assert_eq!(t.s.failure(), Some(&Failure::Fingerprint));
    assert!(keyed(&t.s_up).is_none(), "no keying material was exported");
    assert!(!connected(&t.s_up), "no connection was reported");
    assert!(t.s.seal(b"x").is_err());
}

#[test]
fn red_the_aes_cm_profile_is_refused() {
    let mut t = pair(false);
    t.s.keyed(&[9_u8; 60], dimpl::SrtpProfile::AES128_CM_SHA1_80);
    assert!(matches!(t.s.failure(), Some(Failure::Profile(_))));
    assert!(
        t.s.poll_up().is_none(),
        "nothing exported for a refused profile"
    );
    let mut fresh = pair(false);
    fresh
        .s
        .keyed(&[9_u8; 56], dimpl::SrtpProfile::AEAD_AES_128_GCM);
    assert!(matches!(
        fresh.s.poll_up(),
        Some(Up::Keyed(SrtpKeying {
            profile: SrtpProfile::AeadAes128Gcm,
            ..
        }))
    ));
}

#[test]
fn red_dtls_from_a_path_with_no_verified_check_is_dropped_and_answered_with_nothing() {
    let mut t = pair(false);
    t.checked_and_bound();
    t.pump(50);
    let stranger = p("192.0.2.66:4444");
    let mut hello = vec![22_u8, 0xfe, 0xfd];
    hello.extend_from_slice(&[0; 60]);
    assert_eq!(t.s.ingest(stranger, &hello, t.now), Verdict::Kept);
    t.s.handle_timeout(t.now + Duration::from_secs(2));
    while let Some((to, _)) = t.s.poll_wire() {
        assert_ne!(
            to, stranger,
            "nothing goes to a path that never proved itself"
        );
    }
    assert_eq!(t.s.bind_path(stranger, t.now), Err(BindRefused::Unchecked));
    assert!(!t.s.may_send_clear(stranger, &[0x80, 0, 0, 0]));
}

#[test]
fn red_a_forged_message_integrity_is_not_heard() {
    let mut t = pair(false);
    let s_ice = creds(S_ICE.0, S_ICE.1);
    t.s.ingest(t.c_path, &check(&s_ice, C_ICE.0, "not-the-password"), t.now);
    assert_eq!(t.s.bind_path(t.c_path, t.now), Err(BindRefused::Unchecked));
    assert!(
        t.s.poll_wire().is_none(),
        "no probe for an unverified check"
    );
    // A check addressed to another session's ufrag, even with this pwd, is not heard either.
    t.s.ingest(
        t.c_path,
        &check(&creds("other", S_ICE.1), C_ICE.0, S_ICE.1),
        t.now,
    );
    assert_eq!(t.s.bind_path(t.c_path, t.now), Err(BindRefused::Unchecked));
}

#[test]
fn red_a_spoofed_or_replayed_check_cannot_bind_a_victim_address() {
    // The peer knows the local pwd (it is in the answer); a spoofed source or a replayed check
    // carries a valid MESSAGE-INTEGRITY. The victim never answers core's probe, so the path stays
    // unproven: no bind, no DTLS, no media toward it.
    let mut t = pair(false);
    let victim = p("192.0.2.10:9");
    let honest = check(&creds(S_ICE.0, S_ICE.1), C_ICE.0, S_ICE.1);
    assert_eq!(
        t.s.ingest(victim, &honest, t.now),
        Verdict::Raw,
        "the check is heard"
    );
    assert_eq!(
        t.s.ingest(victim, &honest, t.now),
        Verdict::Raw,
        "and replayed"
    );
    assert_eq!(t.s.bind_path(victim, t.now), Ok(Bind::WhenProven));
    let probes: Vec<_> = std::iter::from_fn(|| t.s.poll_wire()).collect();
    assert_eq!(probes.len(), 1, "one small probe, not one per replay");
    assert!(probes.iter().all(|(to, d)| *to == victim && is_probe(d)));
    for _ in 0..100 {
        t.now += Duration::from_millis(100);
        t.s.handle_timeout(t.now);
    }
    assert_eq!(t.s.bound_path(), None, "never bound");
    assert!(
        !t.s.may_send_clear(victim, &[0x80, 0, 0, 0]),
        "no media to the victim"
    );
    let mut hello = vec![22_u8, 0xfe, 0xfd];
    hello.extend_from_slice(&[0; 60]);
    t.s.ingest(victim, &hello, t.now);
    while let Some((to, d)) = t.s.poll_wire() {
        assert!(
            to == victim && is_probe(&d),
            "only probes, never DTLS, toward the victim"
        );
    }
}

#[test]
fn red_a_success_response_with_an_unknown_transaction_id_or_wrong_key_or_path_proves_nothing() {
    let mut t = pair(false);
    let honest = check(&creds(S_ICE.0, S_ICE.1), C_ICE.0, S_ICE.1);
    t.s.ingest(t.c_path, &honest, t.now);
    assert_eq!(t.s.bind_path(t.c_path, t.now), Ok(Bind::WhenProven));
    let (_, probe) = t.s.poll_wire().unwrap();

    let mut unknown = probe.clone();
    unknown[8] ^= 0xff;
    t.s.ingest(t.c_path, &answer(&unknown, C_ICE.1), t.now);
    assert_eq!(t.s.bound_path(), None, "unknown transaction id");

    t.s.ingest(t.c_path, &answer(&probe, "not-the-remote-password"), t.now);
    assert_eq!(
        t.s.bound_path(),
        None,
        "MESSAGE-INTEGRITY not under the remote pwd"
    );

    t.s.ingest(p("203.0.113.200:1"), &answer(&probe, C_ICE.1), t.now);
    assert_eq!(t.s.bound_path(), None, "answered from another path");

    t.s.ingest(t.c_path, &answer(&probe, C_ICE.1), t.now);
    assert_eq!(
        t.s.bound_path(),
        Some(t.c_path),
        "the real answer proves it"
    );
}

#[test]
fn red_a_rebind_needs_proof_of_the_new_path_and_then_dtls_follows() {
    let mut t = pair(false);
    t.checked_and_bound();
    t.pump(50);
    assert!(connected(&t.s_up));
    let new = p("203.0.113.77:61000");
    let s_ice = creds(S_ICE.0, S_ICE.1);

    t.s.ingest(new, &check(&s_ice, C_ICE.0, "forged"), t.now);
    assert_eq!(
        t.s.rebind_path(t.c_path, new, t.now),
        Err(BindRefused::Unchecked)
    );
    assert_eq!(
        t.s.rebind_path(p("198.51.100.200:1"), new, t.now),
        Err(BindRefused::NotBound)
    );

    t.s.ingest(new, &check(&s_ice, C_ICE.0, S_ICE.1), t.now);
    assert_eq!(t.s.rebind_path(t.c_path, new, t.now), Ok(Bind::WhenProven));
    assert_eq!(t.s.bound_path(), Some(t.c_path), "not moved before proof");
    let probe = std::iter::from_fn(|| t.s.poll_wire())
        .find(|(to, d)| *to == new && is_probe(d))
        .expect("probe to the new path")
        .1;
    t.s.ingest(new, &answer(&probe, C_ICE.1), t.now);
    assert_eq!(t.s.bound_path(), Some(new));
    t.s.seal(b"after the switch").unwrap();
    let sent: Vec<_> = std::iter::from_fn(|| t.s.poll_wire()).collect();
    assert!(!sent.is_empty());
    assert!(
        sent.iter().all(|(to, _)| *to == new),
        "DTLS follows the rebind"
    );
}

#[test]
fn red_consent_that_stops_being_answered_ends_the_association() {
    let mut t = pair(false);
    t.checked_and_bound();
    t.pump(50);
    assert!(connected(&t.s_up));
    t.answer_probes = false;
    t.pump(3_500);
    assert_eq!(t.s.failure(), Some(&Failure::ConsentExpired));
    assert!(!t.s.may_send_clear(t.c_path, &[0x80, 0, 0, 0]));
}

#[test]
fn consent_that_keeps_being_answered_keeps_the_association() {
    let mut t = pair(false);
    t.checked_and_bound();
    t.pump(4_000);
    assert_eq!(t.s.failure(), None);
    assert_eq!(t.s.bound_path(), Some(t.c_path));
}

#[test]
fn dtls_that_beats_the_proof_from_a_heard_path_is_kept_and_replayed() {
    let mut t = pair(false);
    t.checked_and_bound();
    // The client's ClientHello is out before the server has proven the client's path.
    t.c.handle_timeout(t.now);
    let mut server_probe = None;
    while let Some((to, d)) = t.s.poll_wire() {
        if is_probe(&d) && to == t.c_path {
            server_probe = Some(d);
        }
    }
    while let Some((_, d)) = t.c.poll_wire() {
        if is_probe(&d) {
            let a = answer(&d, S_ICE.1);
            t.c.ingest(t.s_path, &a, t.now);
        } else {
            assert_eq!(t.s.ingest(t.c_path, &d, t.now), Verdict::Kept);
        }
    }
    t.s.ingest(t.c_path, &answer(&server_probe.unwrap(), C_ICE.1), t.now);
    t.pump(50);
    assert!(connected(&t.s_up) && connected(&t.c_up));
}

#[test]
fn only_a_heard_path_gets_media_up_and_only_the_bound_path_gets_media_out() {
    let mut t = pair(false);
    assert_eq!(
        t.s.ingest(t.c_path, &[0x80, 0x6f, 0, 1], t.now),
        Verdict::Kept
    );
    let honest = check(&creds(S_ICE.0, S_ICE.1), C_ICE.0, S_ICE.1);
    assert_eq!(t.s.ingest(t.c_path, &honest, t.now), Verdict::Raw);
    assert_eq!(
        t.s.ingest(t.c_path, &[0x80, 0x6f, 0, 1], t.now),
        Verdict::Raw
    );
    let success = [
        0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ];
    assert!(
        t.s.may_send_clear(t.c_path, &success),
        "answering a heard check"
    );
    assert!(
        !t.s.may_send_clear(t.c_path, &[0x80, 0, 0, 0]),
        "no media before the bind"
    );
}

#[test]
fn the_session_cert_shows_only_its_fingerprint_and_dimpl_never_holds_the_key() {
    let cert = SessionCert::mint().unwrap();
    assert_eq!(cert.fingerprint(), sha256(cert.public_der()));
    let shown = format!("{cert:?}");
    assert!(shown.contains(&hex(&cert.fingerprint())));
    assert!(!shown.contains("key"), "{shown}");
    let handed = cert.dimpl();
    assert!(
        handed.private_key.starts_with(b"busbar-dtls-key-handle:"),
        "a handle, not key bytes"
    );
    let k = SrtpKeying {
        profile: SrtpProfile::AeadAes128Gcm,
        material: Zeroizing::new(vec![0xAB; 56]),
    };
    assert!(
        !format!("{k:?}").contains("171"),
        "keying material never printed"
    );
}

#[test]
fn red_the_key_provider_refuses_raw_key_bytes() {
    let pkcs8 = ::ring::signature::EcdsaKeyPair::generate_pkcs8(
        &::ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &SystemRandom::new(),
    )
    .unwrap();
    assert!(super::ring::provider()
        .key_provider
        .load_private_key(pkcs8.as_ref())
        .is_err());
    let cert = SessionCert::mint().unwrap();
    let handle = cert.dimpl().private_key;
    assert!(super::ring::provider()
        .key_provider
        .load_private_key(&handle)
        .is_ok());
    drop(cert);
    assert!(
        super::ring::provider()
            .key_provider
            .load_private_key(&handle)
            .is_err(),
        "a dropped certificate's handle resolves to nothing"
    );
}

#[test]
fn red_a_flood_of_sources_holds_both_maps_at_their_caps_and_the_real_path_still_proves_and_moves() {
    let mut t = pair(false);
    let honest = check(&creds(S_ICE.0, S_ICE.1), C_ICE.0, S_ICE.1);
    t.s.ingest(t.c_path, &honest, t.now);
    assert_eq!(t.s.bind_path(t.c_path, t.now), Ok(Bind::WhenProven));
    let (_, real_probe) = t.s.poll_wire().unwrap();

    // MAX_PROBES + 1 distinct spoofed sources, each with a verified (replayed) check.
    for i in 0..=MAX_PROBES {
        let spoofed = SocketAddr::from(([192, 0, 2, u8::try_from(i).unwrap()], 9));
        t.now += Duration::from_millis(1);
        t.s.ingest(spoofed, &honest, t.now);
    }
    assert_eq!(t.s.heard.len(), MAX_HEARD_PATHS, "heard held at its cap");
    assert_eq!(t.s.probes.len(), MAX_PROBES, "probes held at their cap");
    assert_eq!(
        t.s.ingest(t.c_path, &[0x80, 0x6f, 0, 1], t.now),
        Verdict::Raw,
        "the awaited path is still heard: the flood evicted spoofed paths, not it"
    );

    // The real path's check, in flight since before the flood, still completes.
    t.s.ingest(t.c_path, &answer(&real_probe, C_ICE.1), t.now);
    assert_eq!(t.s.bound_path(), Some(t.c_path));

    // And a real NEW path after the flood can still be heard, proven and moved to.
    let new = p("203.0.113.77:61000");
    t.s.ingest(new, &honest, t.now);
    assert_eq!(t.s.rebind_path(t.c_path, new, t.now), Ok(Bind::WhenProven));
    let probe = std::iter::from_fn(|| t.s.poll_wire())
        .find(|(to, d)| *to == new && is_probe(d))
        .expect("probe to the new path")
        .1;
    t.s.ingest(new, &answer(&probe, C_ICE.1), t.now);
    assert_eq!(t.s.bound_path(), Some(new));
    assert!(t.s.heard.len() <= MAX_HEARD_PATHS && t.s.probes.len() <= MAX_PROBES);
}

#[test]
fn red_heard_paths_and_probes_age_out_with_consent() {
    let mut t = pair(false);
    let honest = check(&creds(S_ICE.0, S_ICE.1), C_ICE.0, S_ICE.1);
    for i in 0..5_u8 {
        t.s.ingest(SocketAddr::from(([192, 0, 2, i], 9)), &honest, t.now);
    }
    assert_eq!(t.s.heard.len(), 5);
    t.now += CONSENT_TIMEOUT + Duration::from_secs(1);
    t.s.handle_timeout(t.now);
    assert!(t.s.heard.is_empty(), "heard paths age out");
    assert!(t.s.probes.is_empty(), "unanswered probes age out");
}
