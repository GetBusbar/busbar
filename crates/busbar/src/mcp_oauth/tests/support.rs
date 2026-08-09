// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test-only fixture: a fake authorization server that mints REAL tokens.
//!
//! Every token in this battery is genuinely signed — ES256 over a keypair generated in-process, or
//! RS256 over a checked-in test key — and the key set the resource server is built from is derived
//! from the same keypair. Nothing is stubbed and nothing is mocked out, which matters here more than
//! usual: a battery whose "valid token" is a hand-written string proves only that string handling
//! works, and a battery whose crypto is faked cannot tell a passing signature check from an absent
//! one. If the signature verification in `jwt.rs` were deleted, the wrong-key test in this battery
//! would go green — which is exactly why that test exists and why the key material here is real.

use super::jwks::JwkSet;
use super::ResourceServer;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair};

/// A checked-in RSA-2048 private key in PKCS#8, base64. Test-only material, generated for this
/// battery and used nowhere else: `ring` cannot generate RSA keys, and RS256 is what Okta, Entra and
/// Auth0 sign access tokens with by default, so the RS256 path has to be exercised against a real
/// key or it is not exercised at all.
const TEST_RSA_PKCS8_B64: &str = concat!(
    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC4QWmzi180QwgZ",
    "Y3gTboXziZJTvESounarTLhqa7lhsFOdu3Bm2z8IGn75hV9IUbI+uOlQlvPOykYA",
    "6NFGfZ/9vplU3se67Un3AFP/qxIY6TLb4DlIe+qAzdOaxZGvv1ouMhgsmALVEW85",
    "/3p8SepTbBkZqgWWpID8xxNTdxyGPOSHcRtH3DEKDWNZkw0roY+tDvKD2rLy1B5y",
    "m6zbYs4FzPqvE4tkIYr+C3hmVOikgnB6nBoMEEuBrJOI9DW3JN1BDagrssEFtd1L",
    "sojAsF+HbVqrQkA/sS8g4Svr9oMdi6AuwvQhsctt2MBkQxDflw2k8zVufLadIrPG",
    "umvoU0cFAgMBAAECggEAAZ0tneud6PzaU+Ca4cX3LwFHVXd8Au9ap80oce5haHFb",
    "8FP5EEmWUQ3Jc/5QPyYKDTCODnYAxSI+Iw4hNYY0OrpZYs7RZxz6Cq51/HKiMW0T",
    "3/LHEVBFG52AfKAPGJ0T3xRm78MQHaboJglLqGUwuFfCcsyf/VDjQhZ+PSPcKpTu",
    "kBm+CUFgBbuK2uO7jfUmpw8pomrrCfUWVo5kKaW1DU+nLQoEZ4hImSMNkjBi9M3R",
    "k4HM1bviQ1tIjvzLqWituDz2otHmLE4/956R2owa9V7RzBCGvZbB7kz47OJZ5Ipz",
    "r+W0wzuCrY+vHQPtjxr3DL+IA6jLIcItXskcxRN7eQKBgQDoRFf3XV0FxaickNAl",
    "6KJQUyOQaHyDVfW+HYjJdkysuLd0SRzflBm2bctGlRY5gxThXc96sshTbK2f1E5S",
    "BCi+wZ4lBmsLCtDMWTqfKpcrgyzzxop/1wxOVFASYfEnWyEEd+0e6seVN/T1cEV7",
    "r4y+ao1bWb7OQIvfeiOUytm13QKBgQDLFS6quQGvcLxdWYf5Fd2PbOS9UQeSRY9n",
    "g84qown11YLYzScxOlqn+XnSGIh5G21UJMpH44a/IKkqqI+q9A1Cya8dZ98ms5GQ",
    "V3J7YHZHzQNyPuLz6gSnu7w0WXEz/1DlPWzQSTAptmRov0pXrwqYU/kMDYKUSfcQ",
    "hIWbOXTnSQKBgAuxHQh7r6oRuBohhAjUfA81EC49xD7MPfGTBQa3KMbtCXcWExkC",
    "GIVBY6Eq8hJ1EcECeuY/R6xDZT4Nbt/cC70GfBJ7DzpgEgCnYTcP6soq8UFYNjKX",
    "PaxXvCwguAX2JWRXMR2ETgWp6m/MdgLy5E/Vh0YY72zsfN4EBPSBfZIVAoGAY7Cb",
    "Pu0geanCnaR0jf6Ay4Yt5w0exVvmIG9gRifQnN/ZomlawtydYfWiKlMmsySWj4ab",
    "0ZxMKghzYmBqXgX9eHqevrWdolblrtBuf0gD6A0oku1x5UBMVrZelegOHPNJF68G",
    "elxjCybgtVapvM9NSSd3isYbAoYohPA40dDrpRkCgYA0WCglWZZJmBuRdP+1SLDj",
    "WahuXxx3o9k9ALLaZvxBIMowJdl/rEuO1iSeQnNqq6wUvxTORL+ZeNu3mgucN7BB",
    "PWSBR3IhOltEsjiS9QnleIIeCQej9dJmNvAq7v4g7vfBrsA+/ulU/DcFPDLRtBk1",
    "L3Q0yo0BKw0sJIEZHiJL9Q==",
);

/// busbar's identity in this battery — the audience every valid token must carry.
pub(crate) const BUSBAR_RESOURCE: &str = "https://busbar.acme.com/mcp";
/// The audience of a DIFFERENT service the same IdP legitimately serves. The confused-deputy test
/// mints for this and expects a refusal.
pub(crate) const OTHER_RESOURCE: &str = "https://billing.acme.com/api";
/// The operator's IdP.
pub(crate) const ISSUER: &str = "https://acme.okta.com/oauth2/default";
/// A fixed "now" so every expiry assertion is deterministic; 2026-08-08T00:00:00Z.
pub(crate) const NOW: u64 = 1_786_060_800;

/// The signing half of a fake authorization server.
enum Signer {
    Ec(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

/// A fake authorization server: one signing key, its published key set, and a token mint.
pub(crate) struct TestIdp {
    pub(crate) issuer: String,
    pub(crate) kid: String,
    signer: Signer,
    rng: SystemRandom,
}

impl TestIdp {
    /// An ES256 IdP with a freshly generated P-256 keypair. Fresh per call, so "signed by the wrong
    /// key" is produced by building a second IdP rather than by corrupting bytes — a corrupted
    /// signature and a valid signature from an untrusted key are different attacks and only the
    /// second one is interesting.
    pub(crate) fn ec(issuer: &str, kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate P-256 key");
        let key = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .expect("parse generated P-256 key");
        Self {
            issuer: issuer.to_string(),
            kid: kid.to_string(),
            signer: Signer::Ec(key),
            rng,
        }
    }

    /// An RS256 IdP over the checked-in test key.
    pub(crate) fn rsa(issuer: &str, kid: &str) -> Self {
        let der = base64::engine::general_purpose::STANDARD
            .decode(TEST_RSA_PKCS8_B64)
            .expect("test RSA key is base64");
        let key = RsaKeyPair::from_pkcs8(&der).expect("test RSA key is valid PKCS#8");
        Self {
            issuer: issuer.to_string(),
            kid: kid.to_string(),
            signer: Signer::Rsa(key),
            rng: SystemRandom::new(),
        }
    }

    /// The JWKS document this IdP publishes, derived from the private key so the two cannot drift.
    pub(crate) fn jwks(&self) -> String {
        match &self.signer {
            Signer::Ec(key) => {
                // ring hands back the uncompressed SEC1 point 0x04 || X || Y; a JWK wants X and Y
                // separately, base64url.
                let point = key.public_key().as_ref();
                assert_eq!(point.len(), 65, "uncompressed P-256 point");
                let x = URL_SAFE_NO_PAD.encode(&point[1..33]);
                let y = URL_SAFE_NO_PAD.encode(&point[33..65]);
                serde_json::json!({"keys": [{
                    "kty": "EC", "crv": "P-256", "kid": self.kid, "use": "sig",
                    "x": x, "y": y,
                }]})
                .to_string()
            }
            Signer::Rsa(_) => serde_json::json!({"keys": [{
                "kty": "RSA", "kid": self.kid, "use": "sig",
                "n": TEST_RSA_N, "e": "AQAB",
            }]})
            .to_string(),
        }
    }

    /// The `alg` this IdP signs with.
    fn alg(&self) -> &'static str {
        match self.signer {
            Signer::Ec(_) => "ES256",
            Signer::Rsa(_) => "RS256",
        }
    }

    /// Mint a genuinely signed token over `claims`, with this IdP's own header.
    pub(crate) fn mint(&self, claims: &serde_json::Value) -> String {
        self.mint_with_header(
            &serde_json::json!({"alg": self.alg(), "typ": "at+jwt", "kid": self.kid}),
            claims,
        )
    }

    /// Mint with a caller-supplied header, so a test can lie about `alg` or `kid` while the
    /// signature stays real.
    pub(crate) fn mint_with_header(
        &self,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> String {
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig = match &self.signer {
            Signer::Ec(key) => key
                .sign(&self.rng, signing_input.as_bytes())
                .expect("ES256 sign")
                .as_ref()
                .to_vec(),
            Signer::Rsa(key) => {
                let mut out = vec![0u8; key.public().modulus_len()];
                key.sign(
                    &ring::signature::RSA_PKCS1_SHA256,
                    &self.rng,
                    signing_input.as_bytes(),
                    &mut out,
                )
                .expect("RS256 sign");
                out
            }
        };
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }
}

/// The RSA modulus of [`TEST_RSA_PKCS8_B64`], base64url — the public half, as a JWKS would publish
/// it.
const TEST_RSA_N: &str = concat!(
    "uEFps4tfNEMIGWN4E26F84mSU7xEqLp2q0y4amu5YbBTnbtwZts_CBp--YVfSFGy",
    "PrjpUJbzzspGAOjRRn2f_b6ZVN7Huu1J9wBT_6sSGOky2-A5SHvqgM3TmsWRr79a",
    "LjIYLJgC1RFvOf96fEnqU2wZGaoFlqSA_McTU3cchjzkh3EbR9wxCg1jWZMNK6GP",
    "rQ7yg9qy8tQecpus22LOBcz6rxOLZCGK_gt4ZlTopIJwepwaDBBLgayTiPQ1tyTd",
    "QQ2oK7LBBbXdS7KIwLBfh21aq0JAP7EvIOEr6_aDHYugLsL0IbHLbdjAZEMQ35cN",
    "pPM1bny2nSKzxrpr6FNHBQ",
);

/// An UNSIGNED token: `alg: none` with an empty signature segment, the classic forgery. Built
/// without any IdP, because that is the point — an attacker has no key.
pub(crate) fn unsigned_token(claims: &serde_json::Value) -> String {
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(serde_json::json!({"alg": "none", "typ": "JWT"}).to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

/// A well-formed claim set for the busbar resource, which individual tests then spoil in exactly one
/// way. Building every adversarial token from ONE good baseline is what makes each refusal
/// attributable to the single field the test changed.
pub(crate) fn good_claims() -> serde_json::Value {
    serde_json::json!({
        "iss": ISSUER,
        "sub": "00u1a2b3c4d5e6f7g8h9",
        "aud": BUSBAR_RESOURCE,
        "exp": NOW + 600,
        "iat": NOW - 10,
        "client_id": "0oa9z8y7x6w5v4u3t2s1",
        "name": "Ada Lovelace",
        "scope": "mcp:tools:list mcp:tools:call",
    })
}

/// The same baseline claim set, but valid against the WALL CLOCK.
///
/// [`good_claims`] pins `exp` to [`NOW`] so every expiry assertion in the admission battery is
/// deterministic — that battery passes its own `now` to `admit`. A test that goes through the HTTP
/// stack cannot: the middleware reads `crate::store::now()`, so a token minted against the fixed
/// constant is already long expired and the test would fail for a reason that has nothing to do with
/// what it is asserting. (It did, once, before this existed.)
pub(crate) fn live_claims() -> serde_json::Value {
    let now = crate::store::now();
    let mut claims = good_claims();
    claims["exp"] = serde_json::json!(now + 600);
    claims["iat"] = serde_json::json!(now - 10);
    claims
}

/// A resource server trusting exactly `idp`.
pub(crate) fn resource_server(idp: &TestIdp) -> ResourceServer {
    ResourceServer::build(BUSBAR_RESOURCE, vec![(idp.issuer.clone(), idp.jwks())])
        .expect("resource server builds from a well-formed key set")
}

/// Assert a JWKS document parses, used where a test cares that the fixture itself is sound before it
/// asserts anything about admission.
pub(crate) fn parse_jwks(document: &str) -> JwkSet {
    JwkSet::parse(document).expect("fixture JWKS parses")
}
