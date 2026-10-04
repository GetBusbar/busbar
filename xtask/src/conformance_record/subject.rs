//! THE SUBJECT: a busbar binary built from this checkout, booted on loopback with a config the rig
//! writes, and the client-side plumbing every rig that judges it shares — free ports, `curl`, a
//! throwaway certificate authority, a minted data-plane key.
//!
//! One home for "boot busbar as a conformance subject", so the h2, tls, oidf and jev rigs do not
//! each grow a copy. The a2a rig keeps its own subject (`scripts/a2a-subject/boot.sh`, which its
//! instruments were written against) and only takes the binary from here.
//!
//! Nothing here judges. A boot that never answers, a curl that cannot connect, a key the admin
//! API did not mint: each is an `Err` naming what happened, and the rig's decider says what it
//! means for the verdict.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// `n` distinct loopback ports the OS reported free, all bound at once so no two collide.
pub fn free_ports(n: usize) -> Result<Vec<u16>, String> {
    let held: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("no free loopback port: {e}"))?;
    held.iter()
        .map(|l| {
            l.local_addr()
                .map(|a| a.port())
                .map_err(|e| format!("a bound port has no address: {e}"))
        })
        .collect()
}

/// `n` random bytes, hex. The admin credential of one boot: never a fixed string.
pub fn random_hex(n: usize) -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut buf = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| "the platform RNG failed".to_string())?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// RFC 4648 §5 base64url, unpadded — the JOSE spelling.
pub fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// One answer, as `curl` received it.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// One HTTP request through `curl`, with the body sent as exact bytes (`--data-binary`) and the
/// answer's status and body kept. `extra` is passed to curl as-is (`-k`, `--resolve ...`).
pub fn curl(
    scratch: &Path,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    extra: &[&str],
) -> Result<Reply, String> {
    std::fs::create_dir_all(scratch).map_err(|e| format!("{}: {e}", scratch.display()))?;
    let tag = random_hex(6)?;
    let req = scratch.join(format!("req-{tag}"));
    let out = scratch.join(format!("body-{tag}"));
    let mut c = Command::new("curl");
    c.args(["-sS", "--max-time", "30", "-X", method, "-o"])
        .arg(&out)
        .args(["-w", "%{http_code}"]);
    for (k, v) in headers {
        c.arg("-H").arg(format!("{k}: {v}"));
    }
    if let Some(b) = body {
        std::fs::write(&req, b).map_err(|e| format!("{}: {e}", req.display()))?;
        c.arg("--data-binary").arg(format!("@{}", req.display()));
    }
    c.args(extra).arg(url).stdin(Stdio::null());
    let o = c
        .output()
        .map_err(|e| format!("curl could not be started: {e}"))?;
    let code = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let status: u16 = code.parse().unwrap_or(0);
    let reply = Reply {
        status,
        body: std::fs::read(&out).unwrap_or_default(),
    };
    for p in [&req, &out] {
        let _ = std::fs::remove_file(p);
    }
    if status == 0 {
        return Err(format!(
            "{method} {url}: no answer ({})",
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    Ok(reply)
}

/// A booted busbar. Dropping it stops the process.
pub struct Booted {
    child: Child,
    pub log: PathBuf,
}

impl Booted {
    /// The last lines the subject wrote, for a reason that names why it is not answering.
    pub fn log_tail(&self) -> String {
        tail(&self.log, 15)
    }
}

impl Drop for Booted {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The last `n` lines of a file, joined with ` | ` so they fit in one reason.
pub fn tail(p: &Path, n: usize) -> String {
    let text = std::fs::read_to_string(p).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join(" | ")
}

/// Boot `bin` with `dir/config.yaml` and `dir/providers.yaml`, and wait until `probe` answers
/// anything at all (any status but none). `curl_extra` reaches a TLS listener (`-k`).
pub fn boot(
    bin: &Path,
    dir: &Path,
    config: &str,
    providers: &str,
    env: &[(&str, String)],
    probe: &str,
    curl_extra: &[&str],
) -> Result<Booted, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let cfg = dir.join("config.yaml");
    let prov = dir.join("providers.yaml");
    std::fs::write(&cfg, config).map_err(|e| format!("{}: {e}", cfg.display()))?;
    std::fs::write(&prov, providers).map_err(|e| format!("{}: {e}", prov.display()))?;
    let log = dir.join("boot.log");
    let file = std::fs::File::create(&log).map_err(|e| format!("{}: {e}", log.display()))?;
    let err = file.try_clone().map_err(|e| e.to_string())?;
    let mut c = Command::new(bin);
    c.current_dir(dir)
        .env("BUSBAR_CONFIG", &cfg)
        .env("BUSBAR_PROVIDERS", &prov)
        .stdin(Stdio::null())
        .stdout(file)
        .stderr(err);
    for (k, v) in env {
        c.env(k, v);
    }
    let child = c
        .spawn()
        .map_err(|e| format!("{} could not be started: {e}", bin.display()))?;
    let mut booted = Booted { child, log };
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Ok(Some(st)) = booted.child.try_wait() {
            return Err(format!(
                "the subject exited during boot ({st}): {}",
                booted.log_tail()
            ));
        }
        let mut c = Command::new("curl");
        c.args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "3",
        ])
        .args(curl_extra)
        .arg(probe)
        .stdin(Stdio::null());
        if let Ok(o) = c.output() {
            let code = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !code.is_empty() && code != "000" {
                return Ok(booted);
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let why = format!(
        "the subject never answered {probe} within 60s: {}",
        booted.log_tail()
    );
    drop(booted);
    Err(why)
}

/// `busbar --generate-signing-key` into `dir/signing.key`: the rig is the fleet that owns the key.
pub fn signing_key(bin: &Path, dir: &Path) -> Result<PathBuf, String> {
    let out = Command::new(bin)
        .arg("--generate-signing-key")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("busbar --generate-signing-key could not run: {e}"))?;
    if !out.status.success() || out.stdout.is_empty() {
        return Err(format!(
            "busbar --generate-signing-key failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let p = dir.join("signing.key");
    std::fs::write(&p, &out.stdout).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(p)
}

/// Mint one data-plane key through the admin API the ordinary way, and return its token.
pub fn mint_key(
    scratch: &Path,
    admin: u16,
    admin_token: &str,
    name: &str,
) -> Result<String, String> {
    let bearer = format!("Bearer {admin_token}");
    let body = format!(
        "{{\"name\":{}}}",
        serde_json::to_string(name).unwrap_or_default()
    );
    let r = curl(
        scratch,
        "POST",
        &format!("http://127.0.0.1:{admin}/api/v1/admin/keys"),
        &[
            ("authorization", bearer.as_str()),
            ("content-type", "application/json"),
        ],
        Some(body.as_bytes()),
        &[],
    )?;
    serde_json::from_slice::<Value>(&r.body)
        .ok()
        .and_then(|v| v.get("token").and_then(Value::as_str).map(str::to_string))
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            format!(
                "the admin API minted no key ({}: {})",
                r.status,
                String::from_utf8_lossy(&r.body)
            )
        })
}

/// A throwaway certificate authority and one leaf for `sans`, written as PEM into `dir`:
/// `ca.pem`, `cert.pem` (leaf then CA) and `key.pem`. Valid from yesterday for 90 days, so no
/// scanner grades the subject on a decades-long validity it would never ship with.
pub struct Pki {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// The leaf and the CA, DER, for a rig-owned TLS listener (the oidf rig's IdP stub).
    pub chain_der: Vec<Vec<u8>>,
    /// The leaf's PKCS#8 private key, DER.
    pub key_der: Vec<u8>,
}

pub fn mint_pki(dir: &Path, sans: &[&str]) -> Result<Pki, String> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    let e = |e: rcgen::Error| format!("certificate minting failed: {e}");
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(0);
    let date = |d: i64| {
        let (y, m, dd) = crate::gates::changelog::civil_from_days(d);
        rcgen::date_time_ymd(y as i32, m as u8, dd as u8)
    };

    let ca_key = KeyPair::generate().map_err(e)?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).map_err(e)?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "busbar conformance throwaway CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.not_before = date(days - 1);
    ca_params.not_after = date(days + 90);
    let ca_cert = ca_params.self_signed(&ca_key).map_err(e)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().map_err(e)?;
    let mut leaf_params =
        CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .map_err(e)?;
    leaf_params.distinguished_name.push(
        DnType::CommonName,
        sans.first().copied().unwrap_or("localhost"),
    );
    leaf_params.not_before = date(days - 1);
    leaf_params.not_after = date(days + 90);
    // A revocation pointer, as every publicly issued leaf carries: without one a scanner grades the
    // throwaway certificate (testssl `cert_revocation`, HIGH), not busbar's TLS stack. Nothing
    // fetches it; the scanner judges that the leaf names one.
    leaf_params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
        uris: vec!["http://127.0.0.1/busbar-conformance-ca.crl".to_string()],
    }];
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).map_err(e)?;

    let pki = Pki {
        ca: dir.join("ca.pem"),
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
        chain_der: vec![leaf.der().to_vec(), ca_cert.der().to_vec()],
        key_der: leaf_key.serialize_der(),
    };
    let w = |p: &Path, s: String| std::fs::write(p, s).map_err(|e| format!("{}: {e}", p.display()));
    w(&pki.ca, ca_cert.pem())?;
    w(&pki.cert, format!("{}{}", leaf.pem(), ca_cert.pem()))?;
    w(&pki.key, leaf_key.serialize_pem())?;
    Ok(pki)
}

/// The config every plain subject boots with: a listener, a loopback admin listener, no provider.
/// What a rig needs beyond that (a `tls:` block, an `oauth_as:` block) it appends.
pub fn base_config(listen: &str, admin: u16) -> String {
    format!(
        "listen: \"{listen}\"\nadmin_listen: \"127.0.0.1:{admin}\"\nproviders: {{}}\nmodels: {{}}\n"
    )
}

/// The catalog a subject with no provider boots with.
pub const NO_PROVIDERS: &str = "{}\n";

/// `docker` with `args`, the image pinned by digest. Returns the argv for [`super::rigs::Runner`]'s
/// leg runner, mounting `work` at `/work` and sharing the host network so loopback is the
/// subject's.
pub fn docker_run(image: &str, work: &Path, args: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = ["docker", "run", "--rm", "--network", "host", "-v"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    v.push(format!("{}:/work", work.display()));
    v.push(image.to_string());
    v.extend(args.iter().map(|s| s.to_string()));
    v
}
