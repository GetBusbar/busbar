// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The conformance suite every backend must pass (CRYPTO-SEAM §6 T2). It lives in this public crate
//! (feature `test-support`) so a private build runs the identical source against its swapped-in
//! backend (decision 152). Each check asserts the published known answer or, where the backend
//! refuses the algorithm, an explained [`Error::Unsupported`] and `supports(..) == false`.

#![allow(clippy::missing_panics_doc, clippy::unwrap_used)]

use crate::*;

fn h(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    out.extend(
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()),
    );
    out
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
    // One answer for the external-plugin gate: the backend's required const (IF §5.2 round 13).
    assert_eq!(supports("EXTERNAL_PLUGINS"), EXTERNAL_PLUGINS);
}

/// SHA-2, the audit link, constant-time comparison.
pub fn hash() {
    assert_eq!(
        sha256(b"abc"),
        a::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(
        sha384(b"abc"),
        a::<48>("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
    );
    assert_eq!(
        sha512(b"abc"),
        a::<64>("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    );
    let mut s = Sha256::new();
    s.update(b"a");
    s.update(b"bc");
    assert_eq!(s.finish(), sha256(b"abc"));
    assert_eq!(sha256_parts(&[b"a", b"", b"bc"]), sha256(b"abc"));

    // The link hash is SHA-256 on every backend: the empty-input vector is SHA-256's.
    let empty = link::Hasher::new().finish();
    assert_eq!(
        empty,
        a::<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(empty, sha256(b""));
    // A backend recomputes its own recipe; the retired BLAKE3 and `-sha256` recipes are refused.
    let mut v = link::verifier(link::RECIPE).unwrap();
    v.update(b"abc");
    assert_eq!(v.finish(), sha256(b"abc"));
    assert!(link::verifier("busbar.audit.digest.v7-sha256").is_err());
    assert!(link::verifier("busbar.audit.digest.v7").is_err());
    assert!(link::verifier("busbar.audit.digest.v0").is_err());

    assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"abc", b"ab"));
}

/// HMAC (RFC 4231).
pub fn hmac() {
    let t = hmac_sha256(&[0x0b; 20], b"Hi There").unwrap();
    assert_eq!(
        t,
        a::<32>("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
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
        hmac_sha512(&[0x0b; 20], b"Hi There").unwrap(),
        a::<64>("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
    );
    // RFC 4231 TC2: a 4-byte key, below a FIPS backend's 112-bit minimum.
    let jefe = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    if supports(alg::HMAC_KEY_SHORT) {
        assert_eq!(
            jefe.unwrap(),
            a::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
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
        okm,
        a::<42>(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    );
    // RFC 7914 §11 (c = 1, a 4-byte salt): outside SP 800-132, so a FIPS backend refuses it.
    let mut dk = [0_u8; 64];
    let r = pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut dk);
    if !refused(&r, "PBKDF2") {
        r.unwrap();
        assert_eq!(
            dk,
            a::<64>("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
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
        dk,
        a::<32>("a69b179e3add3c1e0aaf227a0eb3aa2aa8645ab86fecf6ca00c17512697c719e")
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
    // `fill_checked` draws from the same generator, with the backend's error kept (round 21).
    let mut z = [0_u8; 32];
    fill_checked(&mut z).unwrap();
    assert_ne!(z, [0; 32]);
    assert_ne!(z, x);
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
        assert_eq!(r.unwrap(), a::<16>("ab6e47d42cec13bdf53a67b21257bddf"));
        assert_eq!(buf, a::<16>("0388dace60b6a392f328c2b971b2fe78"));
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
    assert_eq!(out, a::<16>("3925841d02dc09fbdc118597196a0b32"));
}

/// Ed25519 (RFC 8032, small order, non-canonical S), ECDSA P-256, RSA, ECDH and the signer seam.
pub fn signatures() {
    let sk = ed25519::SigningKey::from_seed(&a(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ))
    .unwrap();
    let vk = sk.verifying_key();
    assert_eq!(
        vk.to_bytes(),
        a::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    let sig = sk.sign(b"");
    assert_eq!(
        sig,
        a::<64>("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    );
    assert_eq!(
        *sk.seed(),
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
    // Non-canonical encodings (y >= p) do not decode (RFC 8032 §5.1.3), and neither does the
    // negative-zero encoding of the two x = 0 points (y = 1 and y = p - 1 with the sign bit set).
    for bad in [
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
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
    // An encoding with no point on the curve (y = 2) is not refused at load (Q9b: no arithmetic in the
    // decode); it is no weak key either, and it verifies nothing, so it fails closed at the first verify.
    let off = ed25519::VerifyingKey::from_bytes(&a(
        "0200000000000000000000000000000000000000000000000000000000000000",
    ))
    .unwrap();
    assert!(!off.is_weak());
    assert!(off.verify_strict(b"", &sig).is_err());
    // QE: the pinned-key check refuses that key, and every encoding `from_bytes` refuses; it accepts
    // every point, small-order and mixed-order ones included (weakness is `is_weak`'s question).
    assert_eq!(
        ed25519::validate_public_key(&off.to_bytes()),
        Err(Error::Invalid(
            "Ed25519 public key is not a canonical curve point"
        ))
    );
    for bad in [
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        assert!(
            matches!(
                ed25519::validate_public_key(&a(bad)),
                Err(Error::Invalid(_))
            ),
            "{bad}"
        );
    }
    for good in [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "98519eadf35b995233b51b5cd23e9cc5a28b639b5a4af0ec903cb960d81b7819",
    ] {
        assert_eq!(ed25519::validate_public_key(&a(good)), Ok(()), "{good}");
    }
    assert_eq!(
        ed25519::validate_public_key(&vk.to_bytes()),
        Ok(()),
        "the RFC 8032 key"
    );
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
        s_half[32..],
        a::<32>("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")
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
    assert_eq!(rsa::sign_pkcs1_sha256(pk8, MSG).unwrap(), ossl);
    assert_eq!(key.sign_pkcs1_sha256(MSG).unwrap(), ossl);
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
    // `agree` consumes the key, so copy each public key out first.
    let (mut px, mut py) = (Vec::new(), Vec::new());
    px.extend_from_slice(x.public_key());
    py.extend_from_slice(y.public_key());
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
            sha1.unwrap(),
            a::<20>("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
    }
    assert_eq!(
        legacy::hmac_sha1(&[0x0b; 20], b"Hi There").unwrap(),
        a::<20>("b617318655057264e28bc0b6fb378c8ef146be00")
    );
    let md5 = legacy::md5(b"abc");
    if supports(alg::MD5) {
        assert_eq!(md5.unwrap(), a::<16>("900150983cd24fb0d6963f7d28e17f72"));
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
        legacy::rsa_oaep_public_key_check(&pubk).unwrap();
        assert!(legacy::rsa_oaep_public_key_check(b"not a key").is_err());
    } else {
        assert!(refused(&c, "OAEP"));
    }
}

/// The algorithms MIN-3's host crypto table adds (IF §5.2, package H0b): HMAC-SHA384 (RFC 4231),
/// AES-CTR (SP 800-38A F.5.1/F.5.5; FIPS 197 C.3 and appendix B as one block), ECDSA P-256 and
/// P-384 over a point and an SPKI (RFC 6979 A.2.5/A.2.6), RSA over an SPKI, and Ed25519 from
/// PKCS#8 and SPKI (the RFC 8410 encodings of RFC 8032 test 1).
pub fn host_algs() {
    // HMAC-SHA384: RFC 4231 test case 1, and test case 2 (a 4-byte key) where short keys are taken.
    assert_eq!(
        hmac_sha384(&[0x0b; 20], b"Hi There").unwrap(),
        a::<48>("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")
    );
    let jefe = hmac_sha384(b"Jefe", b"what do ya want for nothing?");
    if supports(alg::HMAC_KEY_SHORT) {
        assert_eq!(
            jefe.unwrap(),
            a::<48>("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")
        );
    } else {
        assert!(refused(&jefe, "HMAC"));
    }

    // AES-CTR: four blocks under AES-128 and AES-256, back again, and a partial final block.
    let pt = h(concat!(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    ));
    let ctr = a::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    for (key, want) in [
        (
            h("2b7e151628aed2a6abf7158809cf4f3c"),
            h(concat!(
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff",
                "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
            )),
        ),
        (
            h("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            h(concat!(
                "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5",
                "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"
            )),
        ),
    ] {
        let mut out = vec![0_u8; pt.len()];
        aes_ctr::apply(&key, &ctr, &pt, &mut out).unwrap();
        assert_eq!(out, want);
        let mut back = vec![0_u8; pt.len()];
        aes_ctr::apply(&key, &ctr, &out, &mut back).unwrap();
        assert_eq!(back, pt);
        let mut part = [0_u8; 20];
        aes_ctr::apply(&key, &ctr, &pt[..20], &mut part).unwrap();
        assert_eq!(part[..], want[..20]);
    }
    // One zero block under counter x is E_k(x): the single AES-256 block SRTP's KDF needs (#173),
    // FIPS 197 C.3; and AES-128 (appendix B), equal to `aes_block_encrypt`.
    let mut block = [0_u8; 16];
    aes_ctr::apply(
        &h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        &a("00112233445566778899aabbccddeeff"),
        &[0; 16],
        &mut block,
    )
    .unwrap();
    assert_eq!(block, a::<16>("8ea2b7ca516745bfeafc49904b496089"));
    aes_ctr::apply(
        &h("2b7e151628aed2a6abf7158809cf4f3c"),
        &a("3243f6a8885a308d313198a2e0370734"),
        &[0; 16],
        &mut block,
    )
    .unwrap();
    assert_eq!(block, a::<16>("3925841d02dc09fbdc118597196a0b32"));
    // AES-192 is not offered, and the output is exactly as long as the input.
    assert!(matches!(
        aes_ctr::apply(&[0; 24], &ctr, &[0; 16], &mut block),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        aes_ctr::apply(&[0; 16], &ctr, &[0; 15], &mut block),
        Err(Error::Invalid(_))
    ));

    // ECDSA, RFC 6979 A.2.5 (P-256, SHA-256) and A.2.6 (P-384, SHA-384), message "sample".
    let p256 = h(concat!(
        "04",
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    ));
    let mut p256_spki = h("3059301306072a8648ce3d020106082a8648ce3d030107034200");
    p256_spki.extend_from_slice(&p256);
    let p256_sig = h(concat!(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    ));
    let p384 = h(concat!(
        "04",
        "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64",
        "def8f0ea9055866064a254515480bc13",
        "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1",
        "288b231c3ae0d4fe7344fd2533264720"
    ));
    let mut p384_spki = h("3076301006072a8648ce3d020106052b81040022036200");
    p384_spki.extend_from_slice(&p384);
    let p384_sig = h(concat!(
        "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c",
        "81a648152e44acf96e36dd1e80fabe46",
        "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f",
        "a329c145786e679e7b82c71a38628ac8"
    ));
    ecdsa_p256::verify_fixed(&p256, b"sample", &p256_sig).unwrap();
    ecdsa_p256::verify_fixed_spki(&p256_spki, b"sample", &p256_sig).unwrap();
    assert_eq!(
        ecdsa_p256::verify_fixed_spki(&p256_spki, b"test", &p256_sig),
        Err(Error::Mismatch)
    );
    ecdsa_p384::verify_fixed(&p384, b"sample", &p384_sig).unwrap();
    ecdsa_p384::verify_fixed_spki(&p384_spki, b"sample", &p384_sig).unwrap();
    assert_eq!(
        ecdsa_p384::verify_fixed(&p384, b"test", &p384_sig),
        Err(Error::Mismatch)
    );
    assert_eq!(
        ecdsa_p384::verify_fixed_spki(&p384_spki, b"test", &p384_sig),
        Err(Error::Mismatch)
    );
    // An SPKI form takes only an SPKI of its own curve: a bare point or the other curve is Invalid.
    for r in [
        ecdsa_p256::verify_fixed_spki(&p256, b"sample", &p256_sig),
        ecdsa_p256::verify_fixed_spki(&p384_spki, b"sample", &p256_sig),
        ecdsa_p384::verify_fixed_spki(&p384, b"sample", &p384_sig),
        ecdsa_p384::verify_fixed_spki(&p256_spki, b"sample", &p384_sig),
    ] {
        assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    }

    // RSA over an SPKI: the OpenSSL-made signatures of `signatures` verify under the key's
    // SubjectPublicKeyInfo; its PKCS#1 `RSAPublicKey` is not an SPKI.
    let spki = include_bytes!("../fixtures/rsa2048.spki.der");
    let pkcs1_sig = include_bytes!("../fixtures/rsa_pkcs1.sig");
    rsa::verify_spki(rsa::Scheme::Pkcs1Sha256, spki, MSG, pkcs1_sig).unwrap();
    rsa::verify_spki(
        rsa::Scheme::PssSha256,
        spki,
        MSG,
        include_bytes!("../fixtures/rsa_pss.sig"),
    )
    .unwrap();
    assert_eq!(
        rsa::verify_spki(rsa::Scheme::Pkcs1Sha256, spki, b"other", pkcs1_sig),
        Err(Error::Mismatch)
    );
    let pkcs1 = rsa::SigningKey::from_pkcs8(include_bytes!("../fixtures/rsa2048.pk8.der"))
        .unwrap()
        .public_key();
    assert!(matches!(
        rsa::verify_spki(rsa::Scheme::Pkcs1Sha256, &pkcs1, MSG, pkcs1_sig),
        Err(Error::Invalid(_))
    ));

    // Ed25519 from PKCS#8 and from an SPKI: RFC 8032 test 1 in its RFC 8410 encodings.
    let sk = ed25519::SigningKey::from_pkcs8(&h(concat!(
        "302e020100300506032b657004220420",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )))
    .unwrap();
    assert_eq!(
        *sk.seed(),
        a::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    );
    let sig = sk.sign(b"");
    assert_eq!(
        sig,
        a::<64>("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    );
    let vk = ed25519::VerifyingKey::from_spki(&h(concat!(
        "302a300506032b6570032100",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )))
    .unwrap();
    assert_eq!(vk, sk.verifying_key());
    vk.verify_strict(b"", &sig).unwrap();
    // The bare key and a P-256 SPKI are not Ed25519 SPKIs; a P-256 PKCS#8 is not an Ed25519 key.
    for r in [
        ed25519::VerifyingKey::from_spki(&h(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )),
        ed25519::VerifyingKey::from_spki(&p256_spki),
    ] {
        assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    }
    assert!(matches!(
        ed25519::SigningKey::from_pkcs8(include_bytes!("../fixtures/ec.pk8.der")),
        Err(Error::Invalid(_))
    ));
}

/// A full TLS 1.3 handshake through `tls::*` (the only way to get a config).
#[cfg(feature = "tls")]
pub fn tls_handshake() {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            include_bytes!("../fixtures/ca.der").as_slice(),
        ))
        .unwrap();
    let chain = vec![
        CertificateDer::from(include_bytes!("../fixtures/leaf.der").as_slice()),
        CertificateDer::from(include_bytes!("../fixtures/ca.der").as_slice()),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("../fixtures/leaf.key.der").as_slice(),
    ));
    assert!(tls::signing_key(&key).is_ok());
    // One handshake needs no passing time: the clock stands still at one reading.
    let tickets = tls::ListenerTickets::new("conformance", || 1).unwrap();
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
    host_algs();
    #[cfg(feature = "tls")]
    tls_handshake();
}
