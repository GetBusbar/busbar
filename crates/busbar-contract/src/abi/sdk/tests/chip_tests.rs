// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use zeroize::Zeroizing;

use super::digests::{md5, sha1};
use super::{MysqlAuth, MysqlHandshake};
use crate::abi::sdk::cred::Cred;

fn cred(s: &str) -> Cred {
    Cred::captured(Zeroizing::new(s.as_bytes().to_vec()))
}

#[test]
fn sha1_matches_fips_180_vectors() {
    assert_eq!(
        hex::encode(&sha1(&[b"abc"])[..]),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex::encode(&sha1(&[b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"])[..]),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    assert_eq!(
        hex::encode(&sha1(&[b"ab", b"c"])[..]),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
}

#[test]
fn md5_matches_rfc_1321_vectors() {
    assert_eq!(
        hex::encode(&md5(&[b""])[..]),
        "d41d8cd98f00b204e9800998ecf8427e"
    );
    assert_eq!(
        hex::encode(&md5(&[b"abc"])[..]),
        "900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        hex::encode(
            &md5(&[
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ])[..]
        ),
        "57edf4a22be3c955ac49da2e2107b67a"
    );
}

#[test]
fn scram_sha256_matches_rfc_7677() {
    let c = cred("pencil");
    let (seal, link) = c
        .pg_scram_sha256(
            "n=user,r=rOprNGfwEbeRWgbNEkqO",
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            b"n,,",
        )
        .expect("scram");
    let want = b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    let w = seal.wire();
    assert_eq!(w[0], b'p');
    assert_eq!(&w[1..5], &((want.len() + 4) as i32).to_be_bytes());
    assert_eq!(&w[5..], &want[..]);
    assert!(link.verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="));
}

#[test]
fn scram_refuses_a_wrong_server_signature_a_foreign_nonce_and_a_cheap_iteration_count() {
    let c = cred("pencil");
    let (_, link) = c
        .pg_scram_sha256("n=,r=abc", "r=abcdef,s=QUJD,i=4096", b"n,,")
        .expect("scram");
    assert!(!link.verify("v=AAAA"));
    assert!(c
        .pg_scram_sha256("n=,r=abc", "r=xyz123,s=QUJD,i=4096", b"n,,")
        .is_err());
    assert!(c
        .pg_scram_sha256("n=,r=abc", "r=abcdef,s=QUJD,i=1", b"n,,")
        .is_err());
}

#[test]
fn pg_messages_are_whole() {
    let c = cred("s3cr3t-pw");
    assert_eq!(c.pg_password_message().wire(), b"p\0\0\0\x0es3cr3t-pw\0");
    let md5 = c.pg_md5_message("alice", [1, 2, 3, 4]);
    let body = b"md544a496913670b4e45995c33c22115d02\0";
    assert_eq!(md5.wire()[0], b'p');
    assert_eq!(&md5.wire()[5..], &body[..]);
}

#[test]
fn mysql_scrambles_match_the_server_algorithms() {
    let c = cred("s3cr3t-pw");
    let nonce: Vec<u8> = (1..=20).collect();
    let native = c
        .mysql_auth_switch_response(2, MysqlAuth::Native, &nonce)
        .expect("native");
    assert_eq!(&native.wire()[..4], &[20, 0, 0, 2]);
    assert_eq!(
        hex::encode(&native.wire()[4..]),
        "568193bda62da86a7bd3e297f5d17dc3063744db"
    );
    let sha2 = c
        .mysql_auth_switch_response(3, MysqlAuth::CachingSha2, &nonce)
        .expect("sha2");
    assert_eq!(
        hex::encode(&sha2.wire()[4..]),
        "7256106a8256872cf1c750c6423a0c8aadcec0eeaec5b2c3c8219ef535b97049"
    );
    assert!(
        cred("")
            .mysql_auth_switch_response(2, MysqlAuth::Native, &nonce)
            .expect("empty")
            .wire()
            .len()
            == 4
    );
}

#[test]
fn mysql_handshake_response_lays_out_every_field() {
    let c = cred("s3cr3t-pw");
    let nonce: Vec<u8> = (1..=20).collect();
    let h = MysqlHandshake {
        seq: 1,
        capabilities: 0x0020_8000 | 0x0000_0200,
        max_packet: 16_777_216,
        collation: 45,
        user: b"alice",
        database: Some(b"db"),
        auth: MysqlAuth::Native,
        nonce: &nonce,
        attrs: &[(b"_client_name", b"busbar")],
    };
    let seal = c.mysql_handshake_response(&h).expect("response");
    let w = seal.wire();
    let len = u32::from_le_bytes([w[0], w[1], w[2], 0]) as usize;
    assert_eq!(len, w.len() - 4);
    assert_eq!(w[3], 1);
    let p = &w[4..];
    let caps = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
    assert_eq!(caps & 0x0008_0000, 0x0008_0000, "plugin auth");
    assert_eq!(caps & 0x0000_0008, 0x0000_0008, "connect with db");
    assert_eq!(caps & 0x0010_0000, 0x0010_0000, "connect attrs");
    assert_eq!(&p[4..8], &16_777_216_u32.to_le_bytes());
    assert_eq!(p[8], 45);
    assert_eq!(&p[9..32], &[0; 23]);
    assert_eq!(&p[32..38], b"alice\0");
    assert_eq!(p[38], 20);
    assert_eq!(
        hex::encode(&p[39..59]),
        "568193bda62da86a7bd3e297f5d17dc3063744db"
    );
    assert_eq!(&p[59..62], b"db\0");
    assert_eq!(&p[62..84], b"mysql_native_password\0");
    assert_eq!(p[84], 1 + 12 + 1 + 6);
    assert_eq!(&p[85..], b"\x0c_client_name\x06busbar");
}

#[test]
fn mysql_clear_packet_is_nul_terminated() {
    let c = cred("pw");
    assert_eq!(
        c.mysql_clear_packet(5).expect("clear").wire(),
        b"\x03\0\0\x05pw\0"
    );
}

#[test]
fn resp_auth_is_one_whole_command() {
    let c = cred("pw");
    assert_eq!(
        c.resp_auth(None).wire(),
        b"*2\r\n$4\r\nAUTH\r\n$2\r\npw\r\n"
    );
    assert_eq!(
        c.resp_auth(Some("u")).wire(),
        b"*3\r\n$4\r\nAUTH\r\n$1\r\nu\r\n$2\r\npw\r\n"
    );
}

#[test]
fn ldap_simple_bind_is_rfc_4511() {
    let c = cred("p");
    assert_eq!(
        c.ldap_simple_bind(1, "cn=a").wire(),
        b"\x30\x11\x02\x01\x01\x60\x0c\x02\x01\x03\x04\x04cn=a\x80\x01p"
    );
}

#[test]
fn http_field_values() {
    let c = cred("open sesame");
    assert_eq!(
        c.basic("Aladdin").wire(),
        b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    );
    assert_eq!(c.bearer().wire(), b"Bearer open sesame");
    assert_eq!(c.field().wire(), b"open sesame");
}

#[test]
fn hmac_and_verify() {
    let c = cred("s3cr3t-pw");
    assert_eq!(
        c.hmac_sha256_hex(b"payload").wire(),
        b"99003796343adffe1735817aab1015d14a798895c212c4b06a1962f796949024"
    );
    let raw = hex::decode("99003796343adffe1735817aab1015d14a798895c212c4b06a1962f796949024")
        .expect("hex");
    assert!(c.verify_hmac_sha256(b"payload", &raw));
    assert!(!c.verify_hmac_sha256(b"payloaD", &raw));
    assert!(c.verify_eq(b"s3cr3t-pw"));
    assert!(!c.verify_eq(b"s3cr3t-pX"));
}

#[test]
fn redact_echo_replaces_every_occurrence() {
    let c = cred("hunter2");
    assert_eq!(
        c.redact_echo("Access denied using hunter2 (hunter2)"),
        "Access denied using [redacted] ([redacted])"
    );
    assert_eq!(c.redact_echo("nothing here"), "nothing here");
}

mod rsa_tests {
    use num_bigint::BigUint;

    use super::cred;
    use crate::abi::sdk::chip::digests::sha1;

    /// A throwaway 1024-bit test key (generated for this test only): its public half as MySQL sends
    /// it, and its private exponent so the test can decrypt.
    const PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAeGNPEkihhFwx9XuiW0X6VMAp
LuC5WLdzvwnpZSXfmzok6brqc60v9bnBiCl/T9O5m7/eLcck0usOyQ9eV5p9T4Y4
ijJ7b5W7pYuuReJdv9h481JKwwV75KY1M6dRf7kpYFOCA4Zo8xgdso69qxPTVUXL
9WgH5N2PTtsNkF6eCwIDAQAB
-----END PUBLIC KEY-----
";
    const D: &str = "24bd56479bb7dd8d04844cd5c2d2257379860cd673f32d6a27600a2651367f8e83f4d3e0e82c189d150cd652858955d59692927778c990cfea2ab25a8aa9b2457089a877e2b4980c55432d3cef569412f502c3d1a9a8e5b0f9e5ebb2a527b31b6a24a2ce35e7a7b47d74b1c07adacfcbd28b83dc30fa6614f9bf6bf19da166f1";
    const N: &str = "c078634f1248a1845c31f57ba25b45fa54c0292ee0b958b773bf09e96525df9b3a24e9baea73ad2ff5b9c188297f4fd3b99bbfde2dc724d2eb0ec90f5e579a7d4f86388a327b6f95bba58bae45e25dbfd878f3524ac3057be4a63533a7517fb929605382038668f3181db28ebdab13d35545cbf56807e4dd8f4edb0d905e9e0b";

    fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut c = 0_u32;
        while out.len() < len {
            out.extend_from_slice(&sha1(&[seed, &c.to_be_bytes()])[..]);
            c += 1;
        }
        out.truncate(len);
        out
    }

    /// RFC 8017 7.1.2 decryption, so the test checks what the server would read.
    fn decrypt(ct: &[u8]) -> Vec<u8> {
        let n = BigUint::parse_bytes(N.as_bytes(), 16).expect("n");
        let d = BigUint::parse_bytes(D.as_bytes(), 16).expect("d");
        let k = 128;
        let mut em = BigUint::from_bytes_be(ct).modpow(&d, &n).to_bytes_be();
        while em.len() < k {
            em.insert(0, 0);
        }
        assert_eq!(em[0], 0);
        let (masked_seed, masked_db) = em[1..].split_at(20);
        let seed: Vec<u8> = masked_seed
            .iter()
            .zip(mgf1(masked_db, 20))
            .map(|(a, b)| a ^ b)
            .collect();
        let db: Vec<u8> = masked_db
            .iter()
            .zip(mgf1(&seed, k - 21))
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(&db[..20], &sha1(&[b""])[..], "lHash");
        let one = 20
            + db[20..]
                .iter()
                .position(|&b| b != 0)
                .expect("the 0x01 marker");
        assert_eq!(db[one], 1);
        db[one + 1..].to_vec()
    }

    #[test]
    fn the_rsa_packet_decrypts_to_the_password_xor_the_nonce() {
        let nonce: Vec<u8> = (1..=20).collect();
        let seal = cred("s3cr3t-pw")
            .mysql_rsa_packet(4, &nonce, PEM)
            .expect("encrypts");
        let w = seal.wire();
        assert_eq!(&w[..4], &[128, 0, 0, 4]);
        let plain = decrypt(&w[4..]);
        let want: Vec<u8> = b"s3cr3t-pw\0"
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ nonce[i % nonce.len()])
            .collect();
        assert_eq!(plain, want);
        let again = cred("s3cr3t-pw")
            .mysql_rsa_packet(4, &nonce, PEM)
            .expect("encrypts");
        assert_ne!(again.wire(), w, "a fresh OAEP seed each time");
    }

    #[test]
    fn a_bad_key_or_an_empty_nonce_is_refused() {
        assert!(cred("pw").mysql_rsa_packet(4, b"n", b"not a key").is_err());
        assert!(cred("pw").mysql_rsa_packet(4, b"", PEM).is_err());
    }
}

/// Byte for byte what `mysql_common` 0.37.3 (the 1.5.5 driver's codec) serializes for the same
/// inputs: `HandshakeResponse::new(native scramble, (8, 0, 36), alice, db, native, caps, attrs,
/// 16 MiB)`, and `scramble_323` over the nonce's first 8 bytes.
#[test]
fn mysql_messages_match_the_driver_byte_for_byte() {
    let c = cred("s3cr3t-pw");
    let nonce: Vec<u8> = (1..=20).collect();
    let h = MysqlHandshake {
        seq: 1,
        capabilities: 0x0020_8000 | 0x0000_0200,
        max_packet: 16_777_216,
        collation: 45,
        user: b"alice",
        database: Some(b"db"),
        auth: MysqlAuth::Native,
        nonce: &nonce,
        attrs: &[(b"_client_name", b"busbar")],
    };
    let seal = c.mysql_handshake_response(&h).expect("response");
    assert_eq!(
        hex::encode(&seal.wire()[4..]),
        "08823800000000012d0000000000000000000000000000000000000000000000616c6963650014568193bda62da86a7bd3e297f5d17dc3063744db6462006d7973716c5f6e61746976655f70617373776f726400140c5f636c69656e745f6e616d6506627573626172"
    );
    let old = c
        .mysql_auth_switch_response(3, MysqlAuth::Old, &nonce)
        .expect("old");
    assert_eq!(hex::encode(&old.wire()[4..]), "5e4f5a585d44525000");
    let clear = c
        .mysql_auth_switch_response(3, MysqlAuth::Clear, &nonce)
        .expect("clear");
    assert_eq!(&clear.wire()[4..], b"s3cr3t-pw\0");
    let empty = cred("")
        .mysql_auth_switch_response(3, MysqlAuth::Clear, &nonce)
        .expect("empty");
    assert_eq!(empty.wire(), &[0, 0, 0, 3]);
}

/// AWS's published `get-vanilla` vector (the SigV4 test suite): day key, signature and
/// `SignedHeaders`.
#[test]
fn aws4_matches_the_published_get_vanilla_vector() {
    use super::aws4::Aws4Request;
    let secret = cred("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    let headers = vec![
        ("Host".to_string(), "example.amazonaws.com".to_string()),
        ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
    ];
    let r = Aws4Request {
        region: "us-east-1",
        service: "service",
        method: "GET",
        canonical_uri: "/",
        canonical_query: "",
        headers: &headers,
        payload_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        amzdate: "20150830T123600Z",
        datestamp: "20150830",
    };
    let key = secret.aws4_day_key("20150830", "us-east-1", "service");
    let sig = key.aws4_sign(&r, None).expect("signs");
    assert_eq!(sig.signed_headers, "host;x-amz-date");
    assert_eq!(
        sig.signature.wire(),
        b"5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
    assert!(secret.aws4_verify(
        &r,
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    ));
    assert!(!secret.aws4_verify(&r, "00"));
    let token = cred("tok");
    let with = key.aws4_sign(&r, Some(&token)).expect("signs");
    assert_eq!(with.signed_headers, "host;x-amz-date;x-amz-security-token");
}
