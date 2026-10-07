//! THE oidf RIG — `oidf-oauth2` and `fapi2`, judged by the OpenID Foundation's own conformance
//! suite, SELF-HOSTED at a pinned release and driven by the suite's own runner
//! (`scripts/run-test-plan.py`), against a busbar built from this checkout acting as the
//! authorization server (`oauth_as:`).
//!
//! The claim this rig can support is "passes the suite", never "certified" (owner ruling
//! 2026-09-19, `conformance/registry.toml`): a self-hosted run is the suite's verdict, not the
//! Foundation's listing, which is paid and owner-owned.
//!
//! WHAT RUNS, in order — every step before the subject's is the INSTRUMENT, and a red there is
//! `not-run`:
//!   1. the suite at [`SUITE_TAG`] (checked against [`SUITE_COMMIT`]), cached between runs;
//!   2. its jar, built by its own `builder-compose.yml` (maven image pinned by digest);
//!   3. its server, nginx front and mongodb by its own `docker-compose.yml`, with mongodb pinned by
//!      digest and the server given `host.docker.internal` so it can reach the subject;
//!   4. the SUBJECT: busbar on a TLS listener with an `oauth_as:` block in the FAPI 2.0 posture
//!      (`fapi2: true`) whose issuer is the name the suite reaches it by; the plan's two
//!      `private_key_jwt` clients PROVISIONED in `oauth_as.clients:` with the public halves of
//!      freshly minted ES256 keys (FAPI 2.0 plans have no registration variant: their clients are
//!      static); the resource ([`RESOURCE_PATH`]) behind an OIDC data chain that trusts the AS;
//!   5. `run-test-plan.py` for each plan in [`SUITES`], its per-module results read back.
//!
//! THE JUDGEMENT ([`decide_oidf`]): every module FINISHED with result PASSED, WARNING or REVIEW
//! (REVIEW is the suite's "no failure; a human looks at the screenshot" result) ⇒ `pass`. Any
//! FAILED, INTERRUPTED, SKIPPED or unfinished module ⇒ `fail` naming it. busbar refusing to boot,
//! to publish its metadata or to run the FAPI 2.0 posture ⇒ `fail`. A run that produced no
//! module result at all ⇒ `not-run`.
//!
//! ARCHITECT RULINGS 2026-10-02 (handoff CONFORMANCE-RIGS.md). `oidf-oauth2` is the plan under
//! `openid=plain_oauth` (the registry's words); `fapi2` is the FAPI2 Security Profile plan under the
//! variant the FAPI2 design note (aba9904696, `oauth_as` FAPI knobs) names for busbar's claimed
//! profile: `plain_oauth` + `private_key_jwt` + `dpop` + `plain_fapi`. The two are identical, so the
//! plan runs ONCE and both verdicts are written from that run ([`SUITES`]; [`Runner::run_oidf`]
//! deduplicates on the plan argument). The empty admin chain (so the suite's browser can approve on
//! the consent screen) and the `0.0.0.0` data listener (so the suite's container reaches the
//! subject) live ONLY in this rig's generated subject config and change no product default; the
//! suite tests the issued token against a served route ([`RESOURCE_PATH`]).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::rigs::{fan, Rig, Runner};
use super::subject::{self, b64url, curl};
use super::Outcome;

/// The OpenID Foundation conformance suite, pinned.
pub const SUITE_REPO: &str = "https://gitlab.com/openid/conformance-suite.git";
pub const SUITE_TAG: &str = "release-v5.3.1";
pub const SUITE_COMMIT: &str = "440eec8bac7b12b7389d7ca9cbc459b53507a443";
/// The suite's own compose files name these by floating tag; the rig pins them by digest.
pub const MONGO_IMAGE: &str =
    "mongo@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070";
pub const MAVEN_IMAGE: &str =
    "maven@sha256:c0bfb7e25e0bbe9a1852ffc67e61236e5f80f1eac3dc54e20b9398cea1453fec";
/// Where the suite's own base URL resolves (the suite's docker-compose `base_url`).
pub const SUITE_URL: &str = "https://localhost.emobix.co.uk:8443/";
/// The name the suite's server reaches the subject by.
const SUBJECT_HOST: &str = "host.docker.internal";
/// The test alias, which fixes the suite's callback URL.
const ALIAS: &str = "busbar-conformance";
/// The scope the plan asks for, and the subject grants self-registered clients.
const SCOPE: &str = "conformance";
/// The served subject route the suite calls with an issued access token: `GET /stats`, a route every
/// busbar mounts that requires a busbar token (ARCHITECT ruling 2026-10-02: any served route that
/// requires one). The subject's data chain is an OIDC module trusting this AS's JWKS, so a
/// DPoP-bound token the AS minted, presented with its proof, is what admits the call.
pub const RESOURCE_PATH: &str = "/stats";
/// The subject's identity provider for the AS's own tokens.
const IDP: &str = "fapi-as";

/// One of the plan's two clients: provisioned in the subject's `oauth_as.clients:` with its PUBLIC
/// key, handed to the suite with its PRIVATE key. FAPI 2.0 plans have no client-registration
/// variant (`AbstractFAPI2SPFinalServerTestModule`'s `@VariantParameters` name none at
/// release-v5.3.1): the suite's clients are always static, which is the ARCHITECT's static_client
/// ruling.
pub struct OidfClient {
    pub id: String,
    pub redirect_uri: String,
    pub private: Value,
    pub public: Value,
}

impl OidfClient {
    /// Client `n` (1 or 2). Client 2 is provisioned on the callback with
    /// `?dummy1=lorem&dummy2=ipsum`: the happy flow's second-client leg sends exactly that
    /// `redirect_uri`, and the AS matches redirect URIs exactly.
    pub fn new(n: usize, callback: &str, private: Value, public: Value) -> Self {
        let redirect_uri = if n == 2 {
            format!("{callback}?dummy1=lorem&dummy2=ipsum")
        } else {
            callback.to_string()
        };
        Self {
            id: format!("oidf-suite-client-{n}"),
            redirect_uri,
            private,
            public,
        }
    }
}

/// An RSA private key (RFC 5208 PKCS#8 DER around RFC 8017 `RSAPrivateKey`) as the RFC 7518 s6.3
/// PS256 JWK the suite signs with, and its public half (`n`, `e` only) for the subject's config.
pub fn rsa_jwk_from_pkcs8(der: &[u8], kid: &str) -> Result<(Value, Value), String> {
    let bad = || "the PKCS#8 document is not an RSA private key".to_string();
    // One DER TLV: (tag, content, rest).
    fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, b) = b.split_first()?;
        let (&first, mut b) = b.split_first()?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || b.len() < n {
                return None;
            }
            let len = b[..n]
                .iter()
                .fold(0usize, |a, x| (a << 8) | usize::from(*x));
            b = &b[n..];
            len
        };
        (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
    }
    let expect = |tag: u8, b: &[u8]| -> Result<(Vec<u8>, Vec<u8>), String> {
        match tlv(b) {
            Some((t, content, rest)) if t == tag => Ok((content.to_vec(), rest.to_vec())),
            _ => Err(bad()),
        }
    };
    let (info, _) = expect(0x30, der)?;
    let (_version, rest) = expect(0x02, &info)?;
    let (_algorithm, rest) = expect(0x30, &rest)?;
    let (octets, _) = expect(0x04, &rest)?;
    let (mut ints, _) = expect(0x30, &octets)?;
    let mut members = Vec::new();
    for _ in 0..9 {
        let (int, rest) = expect(0x02, &ints)?;
        let start = int.iter().position(|b| *b != 0).unwrap_or(int.len());
        members.push(b64url(&int[start..]));
        ints = rest;
    }
    // version, n, e, d, p, q, dp, dq, qi
    let public = json!({
        "kty": "RSA", "alg": "PS256", "use": "sig", "kid": kid,
        "n": members[1], "e": members[2],
    });
    let mut private = public.clone();
    for (i, name) in ["d", "p", "q", "dp", "dq", "qi"].iter().enumerate() {
        private[*name] = json!(members[3 + i]);
    }
    Ok((private, public))
}

/// TEST-ONLY RSA-2048 PKCS#8 DER (hex) for the suite's two PS256 clients, one each, minted once
/// for this rig: `ring` (the workspace's one crypto backend) signs and verifies RSA but cannot
/// generate a key, and the rig takes no key-generation tool. They authenticate nothing but the
/// conformance suite's clients against a throwaway subject, whose config holds only their public
/// halves; a pinned conformance client key is what oauth-as's own certified FAPI 2.0 fixture uses.
const SUITE_CLIENT_1_RSA: &str = concat!(
    "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100bbc981a6e415055b27bb",
    "93a54a272496ce84529c37fe26ebf87bf605ee37ac5bce8ba6aa50eca2e1045e2858c62d28f2bd6a27d0374dc6ff3bfd",
    "39d43672e30bb616d5a77a44e4cda142f92777af88245a21081b1a5c42a8f1c3e8abfd08325408ebfa4bea9401e94e95",
    "182b103c4e446cd451ebc8bee07d775137774a7be2b359ea76d224704bc4fef54106151e16ae949a4cc1fef7316f1cb9",
    "ffdae307fc068cafb2875a6ea18d4e5dbccfb2969c63e8931d9d252ed7dd90846e2b705c176768c059ba91455e1def11",
    "930b4945a546b75ed10edd818c04a1ce34f13e01072363c264d17c03add6e0cdf82bb7093e0154fd656c10a983db8386",
    "6503aff0066d020301000102820100552b839e49fc2ebdb53ba22f697e6f5de6b4a5332d421c2d123a46cf51c7f6687d",
    "39619205ba0df5b8a16bf3378eebef8c7145356e9fdc0d8f0bbedabd07466add5f65efdbc8bb6d782284169e76026d5a",
    "6378e5b202fe48d9be5d1d045a5f5935e2b1571541a3cc4953ddee4a22cfecc0df5b78714801516678738bab409d04ab",
    "2f3a5acd217085484cf771d4e72a76b6e18b0c3fb28a69aa8d9f259191ebc57daab017473208ded1af81c2d3d94cb065",
    "c4bdbcd8ab9c0f3825dd7cb3d7995d2da047c82e5e24c759288e5aabe8c347d815f03fc45dd5b3b63a0b9190bbb6feee",
    "025bdf64bc9b6fce6af422ea0b96c4355bc4017b6a6c4f1c9d0c0249ccd09102818100f5745fa92c1612bd5b42070ccc",
    "4ac3c5d9863fa528ae5cdba8f0b744797fdfc241fc94936cf1a3f97f6d5fdb4fc513dee5df7c68beefc297050135649f",
    "60d31304d40808d3ddcc1b1063b7cfd06e193704da0d9c9db50728047eed37f22c5212f9172971817f1ee594da45ea34",
    "8839327dbd423e64385004686c13072d5f357b02818100c3dae0f3c8888b4ee02416774421b42562d954d29b85d2da08",
    "578c6d57617ae81ffad3cc85d0e92ceaf61efe30c2da5309573d0275d06359981caf05b609eeadf840e1e63069fd3df8",
    "46c90c99a4bd6c5fc0f1f952cd398175ad3ebc5342d8dea09b5e5c7e6d8b498ad59966b28190206b020bd846beecb8bf",
    "4a9d3b4349cb370281803bf9244a84901c2212432ecfccb6d3e0eac66794a63cfc495b9cfd5a88c95ad5ef2394f5f49f",
    "922e2b19815b67c1429aaad61162d28c68a257c1b4d7122e2944b3604f5a40d227c5d11a5c56359a4124f555860fe764",
    "cd0bd5156246d2304c1980ad4d1e03c318bc85c35363e754058db5b56193370f9f5584622bc00c310033028181008269",
    "e1b692c65134d14d56644e4abf00d2047355d5d7536279818a7158690185459e28a01c4ed2a5654343b9f0d01ebe820e",
    "c4023a5eeb78c22fff5f272b0ff269c71264cbc217adc6ffa36a2f78a1e56311404ecb92fa02b95005e132f3e522c101",
    "13e135124e5847091a1f67279cc7e9593077f00bbbe6fd017b16f624521b02818039945e5b5cf2a6730bd153200e91e6",
    "b9554fcb0fce9f384bcf371b8d6e05cd4c4d2e8a44691b12d22bca8a0f2cf368f10e1d1f000ad242e9c70f7be8693b4e",
    "1d10689620736aa24e6614c6fb639243c56f2386fefd9d251a56f8412799bf56bb142e27be6b61dc6e253b559c9c09a5",
    "51aa38499f6274694d8f98a6aeaa883b2b",
);
const SUITE_CLIENT_2_RSA: &str = concat!(
    "308204bb020100300d06092a864886f70d0101010500048204a5308204a102010002820101009e8c5ea27bb4087b04fd",
    "526c89b66faa5cb6085ee0173785ef2550d05fc24d827b08680c55e5344b8219092a4fb5d4cdcddbdd81ee99b7c6c2b6",
    "f5e4b7c74746fe412102b4fc6c03a985e9b7728e3f6d4f51efe586947dc05a57eb8aca78f0a980a1ea1e2a4407cfff7a",
    "84451e7e71ea8446c77b94b4e7a37153073e897f4b815292ab628e33e93460c805962a1e3443095af7f1ddb9331b7146",
    "186335b60239a1cb2720df1d00bccabde61aa1c3a20398c6d3c036b5ac25592267c0d8aa8a2c8920f0af0d00c1ca5c76",
    "3da2be4917b6d40d25bf3a33f2651d86c4d3edb91619d78724ac4615af7e1aed8306a0dc877c4f5243a14ffcabc30f76",
    "a54d97943b6b02030100010281ff34e369cef7ca4e5f3e75843a82af3b5c33632346debb8a98c3db9e652c6b9420c7e9",
    "e86fa4937ed4836d66f9e78974e65310fb046d4163b4077b2ed3b0c9491496c936c05e5dbb9027d89463241f1af5b46f",
    "9d7ff6b050707ad3704c62a74416d0d559a2e455ac7a0180d9d32e34d1ec24479f78344710d6e10db3cfd014a9dc6616",
    "331d4b2978b79e71bbb9ec26eb5b8b4bf69681b17d5f529024fde1223834269df18f22ab46e9d3ab82d5f2cccfd8e4b4",
    "78780456d4596e1bd17530e8caf279e4efac0e0f3946f0a6e9f03450aca33f909516a03bc8c4d021198bc2f22a9080fd",
    "84bc376be79c4c90e9b2c5e0efcd800e1dceecccb18dee30c42db8f36d02818100d80501b26abc6b1555c3e01f04f69c",
    "3239eae6d51ea8ed432c56fb5ca1751b9304b4ff8fe812d8ca06f43986a232ddb50ebb73457b9b1c790913191a2f2539",
    "43939520d2c4497cece19367318e9f456e3e5b0e1a4bfc574d977d5fa728f6f9e212ffaae4353e746e92d3417b889204",
    "dccf5c8730990549bbcb1038240043b6ed02818100bbe46119c58ddf690fe99c0e9a3d524812141d2441156f0a37d476",
    "90362dc5b3af577005a3eae75d695ff8772e0bdad916aab42a191bf1a63b160ea75385bfb7ff34f2a29f886e044e3f66",
    "1a0d0b61962e793850685a1e5ef287b73dc98c542ed7461c8f3fe981d59e183cad47e8af77df6439e8d8a7e50596b80b",
    "48551758b70281800fb59d7ffa1f25b2718043263e5828d7c63a7cfaf6b5d63b525829037d8264b4f65cab512dd1610e",
    "a01ed6a821d78d2403a44227c56b6c50a90648870cf2aa0d6e082450ef916092617d34bdf7df414f591d8a13037fa061",
    "b62899f2301a75e5a8f80ad779bfc6fbdb959d677c71120574d707c5d2fafd77b8b6bf3e6efe7da9028181009fde17c8",
    "67d0e8f069bba92ebb89c582d0ef104492a3fc10c3a421255f13df0d9df955b556dd3df2bb000f56c87509c68084ca3a",
    "af96992b8946a13d39d1a96892daa8403a6148ca9d11507c85f0d31d877958b301b6fbf4698394241c632c1596d16ee7",
    "6bc7f0d2a36b97e5103429686348d2050ea2fc389f1f056a8c0c0b4d02818022e9906acb212eddc09738c8f0e0e5fee8",
    "8b1b919ccbb11ac836175bff442974559984af7d0d4a2f3a7634acb3fb3c168f123a8071424aed3fbe8308bf17486343",
    "da0107594759377c8626684cf4f0d3863c68bad7696905da019aa80f35e358e4e9819a434707c803a8c934f80e60172b",
    "1e4d06ce7a61a3c422661a0acd791d",
);

fn hex(s: &str) -> Result<Vec<u8>, String> {
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
                .ok_or_else(|| "a pinned key is not hex".to_string())
        })
        .collect()
}

/// Suite client `n`'s (1 or 2) PS256 JWK pair, from its pinned key.
pub fn suite_client_key(n: usize) -> Result<(Value, Value), String> {
    let der = match n {
        1 => hex(SUITE_CLIENT_1_RSA)?,
        2 => hex(SUITE_CLIENT_2_RSA)?,
        _ => return Err(format!("the plan has two clients, not client {n}")),
    };
    rsa_jwk_from_pkcs8(&der, &format!("{ALIAS}-{n}"))
}

/// The `kid` of the authorization server's signing key (`oauth_as.key_id`).
pub const AS_KEY_ID: &str = "busbar-conformance-as";

/// A fresh ES256 signing key for the authorization server: its PKCS#8 DER (written base64 into the
/// subject's `oauth_as.signing_key` file) and the JWKS of its public half, which the rig's IdP stub
/// serves to the subject's `oidc` module.
pub fn as_signing_key() -> Result<(Vec<u8>, Value), String> {
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING as ALG};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ALG, &rng).map_err(|_| "ES256 keygen failed")?;
    let pair = EcdsaKeyPair::from_pkcs8(&ALG, pkcs8.as_ref(), &rng)
        .map_err(|_| "ES256 key did not reparse")?;
    let point = pair.public_key().as_ref();
    let jwks = json!({ "keys": [{
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": AS_KEY_ID,
        "x": b64url(&point[1..33]), "y": b64url(&point[33..65]),
    }]});
    Ok((pkcs8.as_ref().to_vec(), jwks))
}

/// RFC 4648 s4 base64 (standard alphabet, padded): what busbar reads `oauth_as.signing_key` as.
pub fn base64_std(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// What the rig's IdP stub answers for `path`: the JWKS at `/jwks`, 404 for anything else.
pub fn idp_reply(path: &str, jwks: &str) -> (u16, String) {
    if path == "/jwks" {
        (200, jwks.to_string())
    } else {
        (404, "{}".to_string())
    }
}

/// THE RIG'S IdP STUB: an HTTPS listener on its OWN loopback port (never one of the subject's: the
/// destination guard keeps a node's own ports off-limits), presenting the rig's leaf certificate,
/// serving the authorization server's JWKS to the subject's `oidc` module. Stops on drop.
pub(super) struct IdpStub {
    pub port: u16,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl IdpStub {
    pub(super) fn start(pki: &subject::Pki, jwks: String) -> Result<Self, String> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let chain = pki
            .chain_der
            .iter()
            .map(|d| rustls_pki_types::CertificateDer::from(d.clone()))
            .collect();
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(pki.key_der.clone()),
        );
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("IdP stub TLS: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("IdP stub TLS: {e}"))?;
        let cfg = Arc::new(cfg);
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("IdP stub bind: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("IdP stub: {e}"))?
            .port();
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("IdP stub: {e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((tcp, _)) => serve_idp(tcp, Arc::clone(&cfg), &jwks),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { port, stop })
    }
}

impl Drop for IdpStub {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// One request on one TLS connection: read the head, answer [`idp_reply`], close.
fn serve_idp(tcp: std::net::TcpStream, cfg: std::sync::Arc<rustls::ServerConfig>, jwks: &str) {
    use std::io::{Read, Write};
    let _ = tcp.set_nonblocking(false);
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    let Ok(conn) = rustls::ServerConnection::new(cfg) else {
        return;
    };
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8192 {
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    let line = String::from_utf8_lossy(&head);
    let path = line.split_whitespace().nth(1).unwrap_or("/");
    let (status, body) = idp_reply(path, jwks);
    let reply = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        if status == 200 { "OK" } else { "Not Found" },
        body.len()
    );
    let _ = tls.write_all(reply.as_bytes());
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// What the subject's config is built from, besides its clients.
#[derive(Clone, Copy)]
pub struct OidfSubject<'a> {
    pub issuer: &'a str,
    /// The listener lines ([`subject::base_config`]).
    pub base: &'a str,
    /// The TLS leaf and key files.
    pub cert: &'a str,
    pub key: &'a str,
    /// The rig CA (PEM) the `oidc` module trusts for its JWKS fetch.
    pub ca_pem: &'a str,
    /// The plugins directory holding the packed `oidc` module.
    pub plugins: &'a str,
    /// The file holding the AS signing key (base64 PKCS#8).
    pub as_key_file: &'a str,
    /// The IdP stub's JWKS URL.
    pub jwks_url: &'a str,
}

/// The subject's config: `base` (listeners), TLS, the authorization server in the FAPI 2.0 posture
/// with the plan's clients provisioned, and a data chain whose only provider is the OIDC module
/// trusting this AS (`jwks_url` over loopback, the rig's CA, the token's `scope` as its role, bound
/// to every pool). The admin chain is the explicit open posture so the suite's browser reaches the
/// consent screen on this loopback subject.
pub fn oidf_subject_config(subject: &OidfSubject<'_>, clients: &[OidfClient]) -> String {
    let OidfSubject {
        issuer,
        base,
        cert,
        key,
        ca_pem,
        plugins,
        as_key_file,
        jwks_url,
    } = *subject;
    let declared: Vec<Value> = clients
        .iter()
        .map(|c| {
            json!({
                "client_id": c.id,
                "redirect_uris": [c.redirect_uri],
                "jwks": { "keys": [c.public] },
            })
        })
        .collect();
    let rest = json!({
        "tls": { "cert": { "file": cert }, "key": { "file": key } },
        "oauth_as": {
            "issuer": issuer,
            "default_grant": [SCOPE],
            "fapi2": true,
            // The rig's own key, so the rig's IdP stub can serve its JWKS.
            "signing_key": { "file": as_key_file },
            "key_id": AS_KEY_ID,
            "clients": declared,
        },
        "identity-providers": {
            IDP: {
                "module": "oidc",
                "settings": {
                    "issuer": issuer,
                    "audience": issuer,
                    "jwks_url": jwks_url,
                    "role_claim": "scope",
                    "ca_cert_pem": ca_pem,
                },
            },
        },
        // The `oidc` module is a DROPPED-IN plugin (no shipped busbar links it): the rig packs it
        // unsigned into `plugins` ([`Runner::oidc_plugin`]). Its JWKS comes from the rig's IdP stub
        // on a loopback port of its own ([`IdpStub`]), never the subject's: the destination guard
        // keeps a node's own ports off-limits (DEST-GUARD #153). 127.0.0.1 is declared as an
        // allowed destination the way an operator declares one, so the fetch is admitted by the
        // connector's guard once the module dials through it (FAPI2.md finding).
        "plugins": { "enabled": true, "dir": plugins, "trust": { "allow_unsigned": true } },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "auth": {
            "chain": [IDP],
            "admin_auth": [],
            "role_bindings": { IDP: { SCOPE: {} } },
        },
    });
    format!("{base}{}", serde_yaml::to_string(&rest).unwrap_or_default())
}

/// The suite's plan configuration for the subject at `issuer`.
pub fn oidf_plan_config(issuer: &str, description: &str, clients: &[OidfClient]) -> Value {
    let client =
        |c: &OidfClient| json!({"client_id": c.id, "scope": SCOPE, "jwks": {"keys": [c.private]}});
    let callback = json!({
        "task": "The AS redirected to the suite's callback",
        "match": format!("{SUITE_URL}test/a/{ALIAS}/callback*"),
        "optional": true,
        "commands": [["wait", "id", "submission_complete", 15]]
    });
    // A refused authorization request is an HTML page at /authorize carrying the literal
    // "Authorization error" (busbar-core-oauth2 `routes::error_page`); the wait fills the module's
    // ExpectXxxErrorPage placeholder. `xpath` because the runner fills only from a real selector.
    let error_page = json!({
        "task": "The AS refused the authorization request with its error page",
        "match": format!("{issuer}/authorize*"),
        "optional": true,
        "commands": [["wait", "xpath", "//*", 10, "Authorization error", "update-image-placeholder"]]
    });
    let browser = |click: Value| {
        json!([{
            "match": format!("{issuer}/*"),
            "tasks": [
                {
                    "task": "The consent screen",
                    "match": format!("{issuer}/consent*"),
                    "optional": true,
                    "commands": [click]
                },
                error_page.clone(),
                callback.clone()
            ]
        }])
    };
    json!({
        "alias": ALIAS,
        "description": description,
        "server": {"discoveryUrl": format!("{issuer}/.well-known/oauth-authorization-server")},
        "client": client(&clients[0]),
        "client2": client(&clients[1]),
        "resource": {"resourceUrl": format!("{issuer}{RESOURCE_PATH}")},
        "browser": browser(json!(["click", "id", "approve"])),
        "override": {
            "fapi2-security-profile-final-user-rejects-authentication": {
                "browser": browser(json!(["click", "id", "deny"]))
            },
            // Nobody signs in on the first visit; the repeat showing of the same pushed request
            // carries `id="revisit"`, and only then is Approve pressed (`optional`: absent = no-op).
            "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds": {
                "browser": browser(json!([
                    "click", "xpath", "//*[@id='revisit']/following::button[@id='approve']", "optional"
                ]))
            }
        }
    })
}

/// One suite id: the plan it runs and the variant it runs under.
pub struct Plan {
    pub suite: &'static str,
    pub plan: &'static str,
    pub variant: &'static [(&'static str, &'static str)],
}

/// The FAPI 2.0 Security Profile OP posture for an authorization server that is not an OpenID
/// provider: plain OAuth, private_key_jwt client authentication, DPoP sender-constraining, the
/// plain profile, simple authorization requests. Unsigned requests and plain responses are the
/// posture too, but the PLAN sets those two itself: release-v5.3.1's
/// `FAPI2SPFinalTestPlan.testModulesWithVariants` fixes `fapi_request_method=unsigned` and
/// `fapi_response_mode=plain_response` as its baseline variants, and the suite refuses to create
/// the plan when the caller sets either one too ("Variant 'fapi_request_method' has been set by
/// user, but test plan already sets this variant"), so naming them here ran zero modules.
const FAPI2SP_PLAIN_OAUTH: &[(&str, &str)] = &[
    ("openid", "plain_oauth"),
    ("client_auth_type", "private_key_jwt"),
    ("sender_constrain", "dpop"),
    ("fapi_profile", "plain_fapi"),
    ("authorization_request_type", "simple"),
];

/// Every suite id this rig judges. Two ids naming the same plan and variant are ONE run.
pub const SUITES: &[Plan] = &[
    Plan {
        suite: "oidf-oauth2",
        plan: "fapi2-security-profile-final-test-plan",
        variant: FAPI2SP_PLAIN_OAUTH,
    },
    Plan {
        suite: "fapi2",
        plan: "fapi2-security-profile-final-test-plan",
        variant: FAPI2SP_PLAIN_OAUTH,
    },
];

impl Plan {
    /// `plan[k=v][k=v]`, the runner's spelling.
    pub fn arg(&self) -> String {
        let mut s = self.plan.to_string();
        for (k, v) in self.variant {
            s.push_str(&format!("[{k}={v}]"));
        }
        s
    }
}

/// One module's result as `run-test-plan.py` printed it: `(module, status, result)`.
pub fn module_results(log: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for raw in log.lines() {
        let line = strip_ansi(raw);
        let Some(at) = line.find("Test [") else {
            continue;
        };
        let rest = &line[at..];
        let Some((head, tail)) = rest.split_once(" - result ") else {
            continue;
        };
        let result = tail
            .split(['.', ' '])
            .next()
            .unwrap_or_default()
            .to_string();
        let words: Vec<&str> = head.split_whitespace().collect();
        // `Test [p:m] <module> <id> <status>`
        if words.len() < 5 {
            continue;
        }
        out.push((
            words[2].to_string(),
            words[words.len() - 1].to_string(),
            result,
        ));
    }
    out
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            for d in it.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// What the rig measured for one plan run.
#[derive(Debug, Clone)]
pub struct OidfRun {
    /// `Err` = the suite itself never came up, and why.
    pub instrument: Result<(), String>,
    /// `Err` = no subject; `boot_failed` says whether busbar failed (a boot, its metadata, its
    /// registration endpoint) or the rig never got that far (no binary).
    pub subject: Result<(), String>,
    pub boot_failed: bool,
    pub exit: Option<i32>,
    /// `run-test-plan.py`'s output.
    pub log: String,
    pub evidence: String,
}

const GOOD_RESULTS: &[&str] = &["PASSED", "WARNING", "REVIEW"];

pub fn decide_oidf(run: &OidfRun) -> Outcome {
    if let Err(why) = &run.instrument {
        return Outcome::not_run(format!("the OIDF suite is not up: {why}"));
    }
    if let Err(why) = &run.subject {
        return if run.boot_failed {
            Outcome::fail(why.clone(), run.evidence.clone())
        } else {
            Outcome::not_run(format!("no subject: {why}"))
        };
    }
    let results = module_results(&run.log);
    if results.is_empty() {
        let tail: Vec<&str> = run.log.lines().rev().take(5).collect();
        return Outcome::not_run(format!(
            "the plan produced no module result ({}): {}",
            super::rigs::rc(run.exit),
            tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
        ));
    }
    let red: Vec<String> = results
        .iter()
        .filter(|(_, status, result)| {
            status != "FINISHED" || !GOOD_RESULTS.contains(&result.as_str())
        })
        .map(|(m, status, result)| format!("{m} {status}/{result}"))
        .collect();
    if red.is_empty() {
        Outcome::pass(run.evidence.clone())
    } else {
        Outcome::fail(
            format!(
                "{} of {} module(s) not passed: {}",
                red.len(),
                results.len(),
                super::rigs::first_few(&red)
            ),
            run.evidence.clone(),
        )
    }
}

/// A fresh ES256 key as a private JWK and its public half.
pub fn es256_jwk(kid: &str) -> Result<(Value, Value), String> {
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING as ALG};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ALG, &rng).map_err(|_| "ES256 keygen failed")?;
    let pair = EcdsaKeyPair::from_pkcs8(&ALG, pkcs8.as_ref(), &rng)
        .map_err(|_| "ES256 key did not reparse")?;
    let point = pair.public_key().as_ref();
    if point.len() != 65 || point[0] != 4 {
        return Err("ES256 public key is not an uncompressed P-256 point".into());
    }
    // RFC 5915 ECPrivateKey inside the PKCS#8: version 1 (`02 01 01`), then the 32-byte scalar.
    let der = pkcs8.as_ref();
    let marker = [0x02, 0x01, 0x01, 0x04, 0x20];
    let at = der
        .windows(marker.len())
        .position(|w| w == marker)
        .ok_or("the PKCS#8 document carries no ECPrivateKey scalar")?
        + marker.len();
    let d = der
        .get(at..at + 32)
        .ok_or("the ECPrivateKey scalar is short")?;
    let public = json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
        "x": b64url(&point[1..33]), "y": b64url(&point[33..65]),
    });
    let mut private = public.clone();
    private["d"] = json!(b64url(d));
    Ok((private, public))
}

impl Runner {
    pub(super) fn run_oidf(&self) -> BTreeMap<String, Outcome> {
        let rig = Rig::Oidf;
        let ids = || SUITES.iter().map(|p| p.suite.to_string());
        if let Some(o) = self.missing(rig, &["docker", "git", "python3", "curl", "cargo"]) {
            return fan(ids(), &o);
        }
        let dir = self.work_dir(rig);
        let evidence = self.rel(&dir);
        let blank = |instrument: Result<(), String>| OidfRun {
            instrument,
            subject: Ok(()),
            boot_failed: false,
            exit: None,
            log: String::new(),
            evidence: evidence.clone(),
        };
        let suite = match self.oidf_suite_up() {
            Ok(s) => s,
            Err(e) => return fan(ids(), &decide_oidf(&blank(Err(e)))),
        };
        let out = self.oidf_runs(&suite, &dir, &blank);
        let _ = self.compose(&suite, &["down"], "suite-down");
        out
    }

    /// `docker compose -p busbar-oidf -f docker-compose.yml -f <pins>` in the suite checkout.
    fn compose(&self, suite: &Path, args: &[&str], leg: &str) -> Option<i32> {
        let pins = suite
            .join("docker-compose.busbar.yml")
            .to_string_lossy()
            .into_owned();
        let mut argv: Vec<&str> = vec![
            "docker",
            "compose",
            "-p",
            "busbar-oidf",
            "-f",
            "docker-compose.yml",
            "-f",
            pins.as_str(),
        ];
        argv.extend_from_slice(args);
        self.leg(Rig::Oidf, leg, &argv, Some(suite), &[])
    }

    /// Fetch (or reuse), build and start the pinned suite; the checkout's path when it answers.
    fn oidf_suite_up(&self) -> Result<std::path::PathBuf, String> {
        let rig = Rig::Oidf;
        let cache = self.cache.join("oidf");
        let suite = cache.join(format!("suite-{SUITE_TAG}"));
        let _ = std::fs::create_dir_all(&cache);
        let have = crate::gitp::git(&suite, &["rev-parse", "HEAD"])
            .map(|h| h.trim() == SUITE_COMMIT)
            .unwrap_or(false);
        if !have {
            let _ = std::fs::remove_dir_all(&suite);
            let s = suite.to_string_lossy().into_owned();
            let c = self.leg(
                rig,
                "suite-fetch",
                &[
                    "git", "clone", "--depth", "1", "--branch", SUITE_TAG, SUITE_REPO, &s,
                ],
                None,
                &[],
            );
            let head = crate::gitp::git(&suite, &["rev-parse", "HEAD"]).unwrap_or_default();
            if c != Some(0) || head.trim() != SUITE_COMMIT {
                return Err(format!(
                    "{SUITE_TAG} could not be fetched at {SUITE_COMMIT} (got `{}`)",
                    head.trim()
                ));
            }
        }
        let write = |name: &str, text: String| {
            std::fs::write(suite.join(name), text).map_err(|e| format!("{name}: {e}"))
        };
        write(
            "builder-compose.busbar.yml",
            format!("services:\n  builder:\n    image: {MAVEN_IMAGE}\n"),
        )?;
        write(
            "docker-compose.busbar.yml",
            format!(
                "services:\n  mongodb:\n    image: {MONGO_IMAGE}\n  server:\n    extra_hosts:\n      - \"{SUBJECT_HOST}:host-gateway\"\n"
            ),
        )?;
        if !suite.join("target/fapi-test-suite.jar").is_file() {
            let m2 = cache.join("m2");
            let _ = std::fs::create_dir_all(&m2);
            let c = self.leg(
                rig,
                "suite-build",
                &[
                    "docker",
                    "compose",
                    "-f",
                    "builder-compose.yml",
                    "-f",
                    "builder-compose.busbar.yml",
                    "run",
                    "--rm",
                    "builder",
                ],
                Some(&suite),
                &[("MAVEN_CACHE", m2.to_string_lossy().into_owned())],
            );
            if c != Some(0) || !suite.join("target/fapi-test-suite.jar").is_file() {
                return Err(format!(
                    "the suite's jar did not build ({})",
                    super::rigs::rc(c)
                ));
            }
        }
        let venv = cache.join("venv");
        if !venv.join("bin/python").is_file() {
            let v = venv.to_string_lossy().into_owned();
            let req = suite
                .join("scripts/requirements.txt")
                .to_string_lossy()
                .into_owned();
            let pip = venv.join("bin/pip").to_string_lossy().into_owned();
            if self.leg(
                rig,
                "runner-venv",
                &["python3", "-m", "venv", &v],
                None,
                &[],
            ) != Some(0)
                || self.leg(
                    rig,
                    "runner-deps",
                    &[&pip, "install", "-q", "-r", &req],
                    None,
                    &[],
                ) != Some(0)
            {
                let _ = std::fs::remove_dir_all(&venv);
                return Err("the suite runner's Python environment could not be built".into());
            }
        }
        if self.compose(&suite, &["up", "-d", "--build"], "suite-up") != Some(0) {
            return Err("`docker compose up` of the suite failed".into());
        }
        let deadline = Instant::now() + Duration::from_secs(300);
        let scratch = self.work_dir(rig).join("http");
        while Instant::now() < deadline {
            if curl(
                &scratch,
                "GET",
                "https://localhost:8443/api/runner/available",
                &[],
                None,
                &["-k"],
            )
            .is_ok_and(|r| r.status == 200)
            {
                return Ok(suite);
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        Err("the suite's API never answered on https://localhost:8443 within 300s".into())
    }

    fn oidf_runs(
        &self,
        suite: &Path,
        dir: &Path,
        blank: &dyn Fn(Result<(), String>) -> OidfRun,
    ) -> BTreeMap<String, Outcome> {
        let rig = Rig::Oidf;
        let mut out = BTreeMap::new();
        let mut done: BTreeMap<String, Outcome> = BTreeMap::new();
        for plan in SUITES {
            let arg = plan.arg();
            if let Some(o) = done.get(&arg) {
                out.insert(plan.suite.to_string(), o.clone());
                continue;
            }
            let mut run = blank(Ok(()));
            match self.busbar() {
                Err(e) => run.subject = Err(e),
                Ok(bin) => {
                    let pdir = dir.join(plan.suite);
                    match self.oidf_subject(&bin, &pdir) {
                        Err(e) => {
                            run.subject = Err(e);
                            run.boot_failed = true;
                        }
                        Ok((booted, stub, config)) => {
                            let venv_py = self.cache.join("oidf/venv/bin/python");
                            let py = venv_py.to_string_lossy().into_owned();
                            let cfg = config.to_string_lossy().into_owned();
                            // The runner writes the plan export INTO this directory and does not
                            // create it: with it absent, every module ran and the script then died
                            // on the export (FileNotFoundError) before printing one result.
                            let export_dir = pdir.join("export");
                            let _ = std::fs::create_dir_all(&export_dir);
                            let export = export_dir.to_string_lossy().into_owned();
                            let leg = format!("run-{}", plan.suite);
                            run.exit = self.leg(
                                rig,
                                &leg,
                                &[
                                    &py,
                                    "scripts/run-test-plan.py",
                                    "--export-dir",
                                    &export,
                                    "--no-parallel",
                                    &arg,
                                    &cfg,
                                ],
                                Some(suite),
                                &[
                                    ("CONFORMANCE_SERVER", SUITE_URL.to_string()),
                                    ("CONFORMANCE_DEV_MODE", "1".to_string()),
                                    ("DISABLE_SSL_VERIFY", "1".to_string()),
                                    ("CI", "1".to_string()),
                                ],
                            );
                            run.log = self.log_text(rig, &leg);
                            run.evidence = self.rel(&pdir);
                            drop(booted);
                            drop(stub);
                        }
                    }
                }
            }
            let o = decide_oidf(&run);
            done.insert(arg, o.clone());
            out.insert(plan.suite.to_string(), o);
        }
        out
    }

    /// The dropped-in `oidc` auth module: its cdylib, built FROM ITS OWN REPO at the rev this
    /// workspace's lock pins (GetBusbar/busbar-auth-oidc), and busbar's own `busbar-plugin-pack`,
    /// built in this checkout; the cdylib is then packed UNSIGNED into `<pdir>/plugins/oidc.tar.gz`.
    /// The plugins directory, or busbar's `Err`.
    ///
    /// NOT `cargo build -p busbar-auth-oidc-plugin` in this workspace: the plugin is only a DEV edge
    /// of the root here, and `cargo build -p` of a dev-only dependency panics cargo 1.98's feature
    /// resolver (exit 101 before anything builds), so the rig never reached the suite. The repo is
    /// found the way the release turnstile's dropped-in cdylibs are: `cargo metadata` names the
    /// pinned checkout's manifest, and the build runs over that repo's own workspace into this
    /// checkout's target dir, so the library lands where the pack step reads it.
    fn oidc_plugin(&self, pdir: &Path) -> Result<std::path::PathBuf, String> {
        let rig = Rig::Oidf;
        let plugins = pdir.join("plugins");
        std::fs::create_dir_all(&plugins).map_err(|e| format!("{}: {e}", plugins.display()))?;
        let root = Some(self.root.as_path());
        let repo = pinned_repo_manifest(&self.root, OIDC_PLUGIN)?;
        let (repo, target) = (
            repo.to_string_lossy().into_owned(),
            self.target.to_string_lossy().into_owned(),
        );
        for (leg, argv) in [
            (
                "oidc-plugin-build",
                &[
                    "cargo",
                    "build",
                    "--manifest-path",
                    repo.as_str(),
                    "-p",
                    OIDC_PLUGIN,
                    "--target-dir",
                    target.as_str(),
                ][..],
            ),
            (
                "plugin-pack-build",
                &[
                    "cargo",
                    "build",
                    "-p",
                    "busbar-plugin-loader",
                    "--features",
                    "pack",
                    "--bin",
                    "busbar-plugin-pack",
                ][..],
            ),
        ] {
            if self.leg(rig, leg, argv, root, &[]) != Some(0) {
                return Err(format!("`{}` failed", argv.join(" ")));
            }
        }
        let debug = self.target.join("debug");
        let lib = debug.join(format!(
            "{}busbar_auth_oidc_plugin{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
        let pack = debug.join("busbar-plugin-pack");
        let (lib, pack) = (
            lib.to_string_lossy().into_owned(),
            pack.to_string_lossy().into_owned(),
        );
        let out = plugins.join("oidc.tar.gz").to_string_lossy().into_owned();
        let argv = [
            pack.as_str(),
            "pack",
            "--lib",
            lib.as_str(),
            "--name",
            "oidc",
            "--alias",
            "oidc",
            "--kind",
            "auth",
            "--version",
            "1.0.0",
            "--publisher",
            "busbar-conformance",
            "--out",
            out.as_str(),
            "--allow-unsigned",
        ];
        if self.leg(rig, "oidc-plugin-pack", &argv, root, &[]) != Some(0) {
            return Err("the oidc plugin could not be packed".into());
        }
        Ok(plugins)
    }

    /// Boot the authorization-server subject with the plan's two clients provisioned, check it runs
    /// the FAPI 2.0 posture, and write the suite's plan configuration. `Err` is busbar's.
    fn oidf_subject(
        &self,
        bin: &Path,
        pdir: &Path,
    ) -> Result<(subject::Booted, IdpStub, std::path::PathBuf), String> {
        let ports = subject::free_ports(2)?;
        let (data, admin) = (ports[0], ports[1]);
        let issuer = format!("https://{SUBJECT_HOST}:{data}");
        let pki = subject::mint_pki(pdir, &[SUBJECT_HOST, "localhost", "127.0.0.1"])?;
        let ca_pem =
            std::fs::read_to_string(&pki.ca).map_err(|e| format!("{}: {e}", pki.ca.display()))?;
        let callback = format!("{SUITE_URL}test/a/{ALIAS}/callback");
        let mut clients = Vec::new();
        for n in 1..=2 {
            // PS256 (RSA): FAPI 2.0's other algorithm, and the only client key from which the suite
            // can build its RS256 negative (`ensure-signed-client-assertion-with-RS256-fails`).
            let (private, public) = suite_client_key(n)?;
            clients.push(OidfClient::new(n, &callback, private, public));
        }
        // The AS signs with the rig's key; the rig's IdP stub serves its JWKS on its own port.
        let (as_key, jwks) = as_signing_key()?;
        let as_key_file = pdir.join("as-signing.key");
        std::fs::write(&as_key_file, base64_std(&as_key))
            .map_err(|e| format!("{}: {e}", as_key_file.display()))?;
        let stub = IdpStub::start(&pki, jwks.to_string())?;
        let plugins = self.oidc_plugin(pdir)?;
        // The data listener is reachable from the suite's container; the admin listener is not.
        let config = oidf_subject_config(
            &OidfSubject {
                issuer: &issuer,
                base: &subject::base_config(&format!("0.0.0.0:{data}"), admin),
                cert: &pki.cert.display().to_string(),
                key: &pki.key.display().to_string(),
                ca_pem: &ca_pem,
                plugins: &plugins.display().to_string(),
                as_key_file: &as_key_file.display().to_string(),
                jwks_url: &format!("https://127.0.0.1:{}/jwks", stub.port),
            },
            &clients,
        );
        let booted = subject::boot(
            bin,
            &pdir.join("subject"),
            &config,
            subject::NO_PROVIDERS,
            &[],
            &format!("https://127.0.0.1:{data}/stats"),
            &["-k"],
        )
        .map_err(|e| format!("the authorization-server subject did not boot: {e}"))?;
        let resolve = format!("{SUBJECT_HOST}:{data}:127.0.0.1");
        let via = ["-k", "--resolve", resolve.as_str()];
        let scratch = pdir.join("http");
        let meta = curl(
            &scratch,
            "GET",
            &format!("{issuer}/.well-known/oauth-authorization-server"),
            &[],
            None,
            &via,
        )
        .map_err(|e| format!("the subject published no authorization-server metadata: {e}"))?;
        let meta: Value = serde_json::from_slice(&meta.body).map_err(|_| {
            format!(
                "the subject's authorization-server metadata ({}) is not JSON",
                meta.status
            )
        })?;
        if meta.get("pushed_authorization_request_endpoint").is_none() {
            return Err(
                "the subject's metadata advertises no PAR endpoint: the FAPI 2.0 posture is not on"
                    .into(),
            );
        }
        let plan_config = oidf_plan_config(
            &issuer,
            &format!(
                "busbar {}",
                super::head_commit(&self.root).unwrap_or_default()
            ),
            &clients,
        );
        let path = pdir.join("plan-config.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&plan_config).unwrap_or_default(),
        )
        .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok((booted, stub, path))
    }
}

/// The oidc plugin's crate, as this workspace's lock names it.
const OIDC_PLUGIN: &str = "busbar-auth-oidc-plugin";

/// The manifest of the WORKSPACE that holds `package` at the rev this checkout's lock pins: the
/// package's own manifest, as `cargo metadata` resolves it in the pinned git checkout, and then the
/// nearest `Cargo.toml` above it that declares `[workspace]` (a fleet repo is a two-crate workspace).
/// `Err` when the lock names no such package or the checkout has no workspace manifest.
pub fn pinned_repo_manifest(root: &Path, package: &str) -> Result<std::path::PathBuf, String> {
    let out = std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("`cargo metadata` could not start: {e}"))?;
    if !out.status.success() {
        return Err(format!("`cargo metadata --locked` exited {}", out.status));
    }
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("`cargo metadata` printed no JSON: {e}"))?;
    let manifest = meta["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["name"].as_str() == Some(package))
        .and_then(|p| p["manifest_path"].as_str())
        .ok_or_else(|| format!("this checkout's lock pins no `{package}`"))?;
    workspace_above(Path::new(manifest))
        .ok_or_else(|| format!("no `[workspace]` manifest above {manifest}"))
}

/// The nearest `Cargo.toml` at or above `manifest`'s directory that declares `[workspace]`.
pub fn workspace_above(manifest: &Path) -> Option<std::path::PathBuf> {
    manifest.ancestors().skip(1).find_map(|dir| {
        let m = dir.join("Cargo.toml");
        std::fs::read_to_string(&m)
            .ok()
            .filter(|t| t.lines().any(|l| l.trim() == "[workspace]"))
            .map(|_| m)
    })
}
