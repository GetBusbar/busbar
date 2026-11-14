// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The conformance suite every backend must pass (CRYPTO-SEAM §6 T2). It lives in this public crate
//! (feature `test-support`) so a private build runs the identical source against its swapped-in
//! backend (decision 152). Each check asserts the published known answer or, where the backend
//! refuses the algorithm, an explained [`Error::Unsupported`] and `supports(..) == false`.

#![allow(clippy::missing_panics_doc, clippy::unwrap_used)]

use crate::*;

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn a<const N: usize>(s: &str) -> [u8; N] {
    h(s).try_into().unwrap()
}

/// Whether `r` is a refusal by the linked backend naming `alg`.
fn refused<T: core::fmt::Debug>(r: &Result<T, Error>, alg: &str) -> bool {
    match r {
        Err(Error::Unsupported(u)) => {
            assert_eq!(u.backend, BACKEND);
            assert!(u.alg.contains(alg), "{u:?}");
            assert!(!u.reason.is_empty());
            true
        }
        _ => false,
    }
}

const MSG: &[u8] = b"busbar fips spike";

/// Identity, self-test and the capability set.
pub fn backend_const() {
    assert!(!BACKEND.is_empty() && BACKEND.len() <= 8);
    assert!(BACKEND
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
    assert!(module_version().starts_with(BACKEND));
    self_test().expect("self-test");
    for name in alg::ALL {
        let _ = supports(name);
    }
}

/// SHA-2, the audit link, constant-time comparison.
pub fn hash() {
    assert_eq!(
        sha256(b"abc").to_vec(),
        h("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(
        sha384(b"abc").to_vec(),
        h("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
    );
    assert_eq!(
        sha512(b"abc").to_vec(),
        h("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    );
    let mut s = Sha256::new();
    s.update(b"a");
    s.update(b"bc");
    assert_eq!(s.finish(), sha256(b"abc"));
    assert_eq!(sha256_parts(&[b"a", b"", b"bc"]), sha256(b"abc"));

    let empty = link::Hasher::new().finish().to_vec();
    match link::RECIPE {
        // BLAKE3 of the empty input.
        "busbar.audit.digest.v7" => assert_eq!(
            empty,
            h("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        ),
        // SHA-256 of the empty input.
        "busbar.audit.digest.v7-sha256" => assert_eq!(
            empty,
            h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        ),
        other => panic!("unknown link recipe {other}"),
    }
    // Every backend recomputes its own recipe and the SHA-256 one; an unknown recipe is refused.
    assert!(link::verifier(link::RECIPE).is_ok());
    let mut v = link::verifier("busbar.audit.digest.v7-sha256").unwrap();
    v.update(b"abc");
    assert_eq!(v.finish(), sha256(b"abc"));
    assert!(link::verifier("busbar.audit.digest.v0").is_err());

    assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"abc", b"ab"));
}

/// HMAC (RFC 4231).
pub fn hmac() {
    let t = hmac_sha256(&[0x0b; 20], b"Hi There").unwrap();
    assert_eq!(
        t.to_vec(),
        h("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
    hmac_sha256_verify(&[0x0b; 20], b"Hi There", &t).unwrap();
    assert_eq!(
        hmac_sha256_verify(&[0x0b; 20], b"Hi there", &t),
        Err(Error::Mismatch)
    );
    let k = HmacSha256Key::new(&[0x0b; 20]).unwrap();
    assert_eq!(k.sign(b"Hi There"), t);
    assert_eq!(k.sign_parts(&[b"Hi ", b"There"]), t);
    k.verify(b"Hi There", &t).unwrap();
    assert_eq!(k.verify(b"Hi there", &t), Err(Error::Mismatch));
    assert_eq!(
        hmac_sha512(&[0x0b; 20], b"Hi There").unwrap().to_vec(),
        h("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
    );
    // RFC 4231 TC2: a 4-byte key, below a FIPS backend's 112-bit minimum.
    let jefe = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    if supports(alg::HMAC_KEY_SHORT) {
        assert_eq!(
            jefe.unwrap().to_vec(),
            h("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    } else {
        assert!(refused(&jefe, "HMAC"));
        assert!(refused(&HmacSha256Key::new(b"Jefe").map(|_| ()), "HMAC"));
    }
}

/// HKDF (RFC 5869) and PBKDF2 (RFC 7914).
pub fn kdf() {
    let mut okm = [0_u8; 42];
    hkdf_sha256(
        &h("000102030405060708090a0b0c"),
        &[0x0b; 22],
        &h("f0f1f2f3f4f5f6f7f8f9"),
        &mut okm,
    )
    .unwrap();
    assert_eq!(
        okm.to_vec(),
        h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
    // RFC 7914 §11 (c = 1, a 4-byte salt): outside SP 800-132, so a FIPS backend refuses it.
    let mut dk = [0_u8; 64];
    let r = pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut dk);
    if !refused(&r, "PBKDF2") {
        r.unwrap();
        assert_eq!(
            dk.to_vec(),
            h("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
        );
    }
    // Inside SP 800-132: every backend answers, bit for bit.
    let mut dk = [0_u8; 32];
    pbkdf2_hmac_sha256(
        b"correct horse battery staple",
        &h("000102030405060708090a0b0c0d0e0f"),
        1000,
        &mut dk,
    )
    .unwrap();
    assert_eq!(
        dk.to_vec(),
        h("a69b179e3add3c1e0aaf227a0eb3aa2aa8645ab86fecf6ca00c17512697c719e")
    );
}

/// The random number generator.
pub fn rng() {
    let (mut x, mut y) = ([0_u8; 32], [0_u8; 32]);
    fill(&mut x).unwrap();
    fill(&mut y).unwrap();
    assert_ne!(x, [0; 32]);
    assert_ne!(x, y);
    assert_ne!(u64().unwrap(), u64().unwrap());
    assert_ne!(random::<16>().unwrap(), [0; 16]);
}

/// AES-GCM (NIST test cases 2 and 14) and the AES block (FIPS 197 appendix B).
pub fn aead() {
    let k128 = Aes128Gcm::new(&[0; 16]).unwrap();
    let k256 = Aes256Gcm::new(&[0; 32]).unwrap();
    let mut c = h("0388dace60b6a392f328c2b971b2fe78");
    k128.open_in_place(
        &[0; 12],
        b"",
        &mut c,
        &a("ab6e47d42cec13bdf53a67b21257bddf"),
    )
    .unwrap();
    assert_eq!(c, [0; 16]);
    let mut c = h("cea7403d4d606b6e074ec5d3baf39d18");
    k256.open_in_place(
        &[0; 12],
        b"",
        &mut c,
        &a("d0d1c8a799996bf0265b98b5d48ab919"),
    )
    .unwrap();
    assert_eq!(c, [0; 16]);
    let mut buf = [0_u8; 16];
    let r = k128.seal_in_place(&[0; 12], b"", &mut buf);
    if refused(&r, "GCM") {
        assert_eq!(buf, [0; 16], "a refused seal must not touch the buffer");
    } else {
        assert_eq!(r.unwrap().to_vec(), h("ab6e47d42cec13bdf53a67b21257bddf"));
        assert_eq!(buf.to_vec(), h("0388dace60b6a392f328c2b971b2fe78"));
    }
    let mut buf = *b"seal with a module-made nonce!!!";
    let (nonce, tag) = k256.seal_random_nonce(b"aad", &mut buf).unwrap();
    assert_ne!(&buf, b"seal with a module-made nonce!!!");
    let mut bad = buf;
    assert_eq!(
        k256.open_in_place(&nonce, b"aaD", &mut bad, &tag),
        Err(Error::Mismatch)
    );
    assert_eq!(bad, [0; 32], "a failed open must not leave plaintext");
    k256.open_in_place(&nonce, b"aad", &mut buf, &tag).unwrap();
    assert_eq!(&buf, b"seal with a module-made nonce!!!");
    let out = aes_block_encrypt(
        &a("2b7e151628aed2a6abf7158809cf4f3c"),
        &a("3243f6a8885a308d313198a2e0370734"),
    )
    .unwrap();
    assert_eq!(out.to_vec(), h("3925841d02dc09fbdc118597196a0b32"));
}

/// Ed25519 (RFC 8032, small order, non-canonical S), ECDSA P-256, RSA, ECDH and the signer seam.
pub fn signatures() {
    let sk = ed25519::SigningKey::from_seed(&a(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ))
    .unwrap();
    let vk = sk.verifying_key();
    assert_eq!(
        vk.to_bytes().to_vec(),
        h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    let sig = sk.sign(b"");
    assert_eq!(
        sig.to_vec(),
        h("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    );
    assert_eq!(
        *sk.to_seed(),
        a::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    );
    vk.verify_strict(b"", &sig).unwrap();
    assert_eq!(vk.verify_strict(b"x", &sig), Err(Error::Mismatch));
    assert!(!vk.is_weak());
    // Non-canonical S (S + L).
    let bad: [u8; 64] = a("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901554c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b");
    assert!(
        vk.verify_strict(b"", &bad).is_err(),
        "non-canonical S accepted"
    );
    // Small-order keys: the identity and an order-8 point.
    for weak in [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    ] {
        let k = ed25519::VerifyingKey::from_bytes(&a(weak)).unwrap();
        assert!(k.is_weak(), "{weak}");
        assert!(k.verify_strict(b"", &sig).is_err());
    }
    // Off-curve and non-canonical encodings do not decode (RFC 8032 §5.1.3).
    for bad in [
        "0200000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        assert!(
            matches!(
                ed25519::VerifyingKey::from_bytes(&a(bad)),
                Err(Error::Invalid(_))
            ),
            "{bad}"
        );
    }
    // Mixed-order (non-weak, not torsion-free) keys decode and are not weak.
    let mixed = ed25519::VerifyingKey::from_bytes(&a(
        "98519eadf35b995233b51b5cd23e9cc5a28b639b5a4af0ec903cb960d81b7819",
    ))
    .unwrap();
    assert!(!mixed.is_weak());
    let g = ed25519::SigningKey::generate().unwrap();
    g.verifying_key().verify_strict(MSG, &g.sign(MSG)).unwrap();

    // ECDSA P-256: an OpenSSL-made signature (known answer for verify), plus round trips.
    let ec_pub = include_bytes!("../fixtures/ec.pub");
    let ec_sig = include_bytes!("../fixtures/ec_asn1.sig");
    ecdsa_p256::verify_asn1(ec_pub, MSG, ec_sig).unwrap();
    assert_eq!(
        ecdsa_p256::verify_asn1(ec_pub, b"other", ec_sig),
        Err(Error::Mismatch)
    );
    let kp = ecdsa_p256::from_pkcs8(include_bytes!("../fixtures/ec.pk8.der")).unwrap();
    assert_eq!(&kp.public_key(), ec_pub);
    ecdsa_p256::verify_fixed(ec_pub, MSG, &kp.sign_fixed(MSG).unwrap()).unwrap();
    ecdsa_p256::verify_asn1(ec_pub, MSG, &kp.sign_asn1(MSG).unwrap()).unwrap();
    let fresh = ecdsa_p256::from_pkcs8(&ecdsa_p256::generate_pkcs8().unwrap()).unwrap();
    ecdsa_p256::verify_fixed(&fresh.public_key(), MSG, &fresh.sign_fixed(MSG).unwrap()).unwrap();
    // Low S: s = n/2 is low, n/2 + 1 is high and normalises to n - s, which still verifies.
    let mut s_half = [0_u8; 64];
    s_half[32..].copy_from_slice(&h(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
    ));
    assert!(ecdsa_p256::is_low_s(&s_half));
    s_half[63] += 1;
    assert!(!ecdsa_p256::is_low_s(&s_half));
    ecdsa_p256::normalize_low_s(&mut s_half);
    assert_eq!(
        s_half[32..].to_vec(),
        h("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")
    );
    for _ in 0..8 {
        let mut sig = kp.sign_fixed(MSG).unwrap();
        ecdsa_p256::normalize_low_s(&mut sig);
        assert!(ecdsa_p256::is_low_s(&sig));
        ecdsa_p256::verify_fixed(ec_pub, MSG, &sig).unwrap();
    }

    // RSA-2048: PKCS#1 v1.5 is deterministic, so the signature equals OpenSSL's byte for byte.
    let pk8 = include_bytes!("../fixtures/rsa2048.pk8.der");
    let key = rsa::SigningKey::from_pkcs8(pk8).unwrap();
    let pubk = key.public_key();
    assert_eq!(key.modulus_len(), 256);
    let ossl = include_bytes!("../fixtures/rsa_pkcs1.sig");
    assert_eq!(rsa::sign_pkcs1_sha256(pk8, MSG).unwrap(), ossl.to_vec());
    assert_eq!(key.sign_pkcs1_sha256(MSG).unwrap(), ossl.to_vec());
    rsa::verify_pkcs1_sha256(&pubk, MSG, ossl).unwrap();
    let pss = include_bytes!("../fixtures/rsa_pss.sig");
    rsa::verify_pss_sha256(&pubk, MSG, pss).unwrap();
    rsa::verify_pss_sha256(&pubk, MSG, &key.sign_pss_sha256(MSG).unwrap()).unwrap();
    assert_eq!(
        rsa::verify_pss_sha256(&pubk, b"other", pss),
        Err(Error::Mismatch)
    );

    // ECDH P-256.
    let (x, y) = (
        ecdh_p256::EphemeralKey::generate().unwrap(),
        ecdh_p256::EphemeralKey::generate().unwrap(),
    );
    let (px, py) = (x.public_key().to_vec(), y.public_key().to_vec());
    assert_eq!(
        ecdh_p256::agree(x, &py).unwrap(),
        ecdh_p256::agree(y, &px).unwrap()
    );

    // The signer seam (§2.6).
    let s = LocalSigner::from_seed(&[7; 32]).unwrap();
    let mut out = Vec::new();
    s.sign(MSG, &mut out).unwrap();
    verify(s.public_key(), MSG, &out).unwrap();
    assert_eq!(verify(s.public_key(), b"x", &out), Err(Error::Mismatch));
    assert_eq!(s.boundary(), Boundary::ThisModule);
    assert_eq!(s.public_key().key_id.len(), 16);
    approve_signer(&s).unwrap();
    let ec = PublicKey::new(SigAlg::EcdsaP256Sha256, &kp.public_key());
    let mut sig = kp.sign_fixed(MSG).unwrap();
    ecdsa_p256::normalize_low_s(&mut sig);
    verify(&ec, MSG, &sig).unwrap();
    // DER signatures and compressed keys are not seam encodings.
    assert!(matches!(
        verify(&ec, MSG, &kp.sign_asn1(MSG).unwrap()),
        Err(Error::Invalid(_))
    ));
    let compressed = PublicKey::new(SigAlg::EcdsaP256Sha256, &kp.public_key()[..33]);
    assert!(matches!(
        verify(&compressed, MSG, &sig),
        Err(Error::Invalid(_))
    ));
}

/// MD5 (RFC 1321), SHA-1 (FIPS 180-4), HMAC-SHA1 (RFC 2202), RSA-OAEP-SHA1.
pub fn legacy_algs() {
    let sha1 = legacy::sha1(b"abc");
    if !refused(&sha1, "SHA") {
        assert_eq!(
            sha1.unwrap().to_vec(),
            h("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
    }
    assert_eq!(
        legacy::hmac_sha1(&[0x0b; 20], b"Hi There")
            .unwrap()
            .to_vec(),
        h("b617318655057264e28bc0b6fb378c8ef146be00")
    );
    let md5 = legacy::md5(b"abc");
    if supports(alg::MD5) {
        assert_eq!(md5.unwrap().to_vec(), h("900150983cd24fb0d6963f7d28e17f72"));
    } else {
        assert!(refused(&md5, "MD5"));
    }
    let pubk = rsa::SigningKey::from_pkcs8(include_bytes!("../fixtures/rsa2048.pk8.der"))
        .unwrap()
        .public_key();
    let c = legacy::rsa_oaep_sha1_encrypt(&pubk, b"pw");
    if supports(alg::RSA_OAEP_SHA1) {
        let c = c.unwrap();
        assert_eq!(c.len(), 256);
        // Randomised padding: two encryptions differ.
        assert_ne!(c, legacy::rsa_oaep_sha1_encrypt(&pubk, b"pw").unwrap());
        assert!(legacy::rsa_oaep_sha1_encrypt(b"not a key", b"pw").is_err());
        assert!(legacy::rsa_oaep_sha1_encrypt(&pubk, &[0; 256]).is_err());
    } else {
        assert!(refused(&c, "OAEP"));
    }
}

/// A full TLS 1.3 handshake through `tls::*` (the only way to get a config).
#[cfg(feature = "tls")]
pub fn tls_handshake() {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            include_bytes!("../fixtures/ca.der").to_vec(),
        ))
        .unwrap();
    let chain = vec![
        CertificateDer::from(include_bytes!("../fixtures/leaf.der").to_vec()),
        CertificateDer::from(include_bytes!("../fixtures/ca.der").to_vec()),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("../fixtures/leaf.key.der").to_vec(),
    ));
    assert!(tls::signing_key(&key).is_ok());
    let tickets = tls::ListenerTickets::new("conformance").unwrap();
    let sc = tls::server_config(|b| {
        let mut c = b.with_no_client_auth().with_single_cert(chain, key)?;
        tickets.install(&mut c);
        Ok(c)
    })
    .unwrap();
    let verifier = tls::server_verifier(Arc::new(roots)).unwrap();
    let cc =
        tls::client_config(|b| Ok(b.with_webpki_verifier(verifier).with_no_client_auth())).unwrap();
    let mut client =
        rustls::ClientConnection::new(cc, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = rustls::ServerConnection::new(sc).unwrap();
    for _ in 0..10 {
        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut &buf[..]).unwrap();
        server.process_new_packets().unwrap();
        let mut buf = Vec::new();
        server.write_tls(&mut buf).unwrap();
        client.read_tls(&mut &buf[..]).unwrap();
        client.process_new_packets().unwrap();
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert!(client.negotiated_cipher_suite().is_some());
    assert!(!tls::webpki_algs().is_empty());
    assert!(!tls::signature_algorithms().all.is_empty());
    // The process default is never installed by the facade.
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
}

/// Every check.
pub fn all() {
    backend_const();
    hash();
    hmac();
    kdf();
    rng();
    aead();
    signatures();
    legacy_algs();
    #[cfg(feature = "tls")]
    tls_handshake();
}
