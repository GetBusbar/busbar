//! Bounded, digest-pinned package download with the job credential.
//!
//! The credential reaches curl only through its stdin configuration: it is never
//! an argument, environment value or file. Redirects are followed here, one hop
//! at a time, and only within the original scheme and authority (as the former
//! same-origin urllib handler did), so the header cannot leave the package origin.
use crate::proc::{self, Result, require};
use crate::sha256::Sha256;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

pub const CURL: &str = "/usr/bin/curl";
const MARKER: &str = "BUSBAR-CURL ";

/// `scheme://authority` of an https URL, rejecting credentials and odd forms.
pub fn origin(url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("package download must use https")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    require(
        !authority.is_empty()
            && !authority.contains('@')
            && authority
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b':')),
        "invalid package download origin",
    )?;
    Ok(format!("https://{}", authority.to_ascii_lowercase()))
}

pub fn same_origin(from: &str, to: &str) -> Result<()> {
    require(
        origin(from)? == origin(to)?,
        "credential download changed origin",
    )
}

fn quoted(value: &str) -> Result<String> {
    require(
        value
            .bytes()
            .all(|c| (0x21..0x7f).contains(&c) && c != b'"' && c != b'\\'),
        "download configuration value has unsupported characters",
    )?;
    Ok(format!("\"{value}\""))
}

/// curl stdin configuration; the only place the credential is written.
pub fn curl_config(url: &str, token: &str) -> Result<String> {
    Ok(format!(
        "url = {}\nheader = {}\nsilent\nshow-error\nproto = \"=https\"\nmax-redirs = 0\n\
         connect-timeout = 90\nspeed-limit = 1\nspeed-time = 90\n\
         write-out = \"%{{stderr}}\\n{MARKER}%{{http_code}} %{{redirect_url}}\\n\"\n",
        quoted(url)?,
        quoted(&format!("JOB-TOKEN:{token}"))?
    ))
}

/// Parse curl's final status line: (http code, redirect target).
pub fn status(stderr: &str) -> Result<(u16, String)> {
    let line = stderr
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix(MARKER))
        .ok_or("download produced no status")?;
    let (code, target) = line.split_once(' ').unwrap_or((line, ""));
    Ok((
        code.parse().map_err(|_| "invalid download status")?,
        target.trim().to_owned(),
    ))
}

pub fn redact(text: &str, token: &str) -> String {
    let mut text = if token.is_empty() {
        text.to_owned()
    } else {
        text.replace(token, "[redacted]")
    };
    text.retain(|c| c == '\n' || c == '\t' || !c.is_control());
    let start = text.len().saturating_sub(4096);
    let start = (start..text.len())
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(text.len());
    text[start..].to_owned()
}

/// Download `url` into a fresh `destination`, enforcing an exact byte count
/// and SHA-256 while streaming (one pass; no second read of the file).
pub fn fetch(url: &str, token: &str, destination: &Path, bytes: u64, sha256: &str) -> Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(proc::O_NOFOLLOW)
        .mode(0o600)
        .open(destination)
        .map_err(|e| format!("{}: {e}", destination.display()))?;
    let mut current = url.to_owned();
    for _ in 0..10 {
        proc::check_interrupted()?;
        output.set_len(0).map_err(|e| e.to_string())?;
        output.rewind().map_err(|e| e.to_string())?;
        let (code, target, hash, received) = transfer(&current, token, &mut output, bytes)?;
        if (300..400).contains(&code) {
            require(!target.is_empty(), "download redirect has no target")?;
            same_origin(url, &target)?;
            current = target;
            continue;
        }
        require(
            code == 200,
            &format!("package download failed with HTTP {code}"),
        )?;
        require(
            received == bytes && hash == sha256,
            "downloaded package differs from its protected pin",
        )?;
        output.sync_all().map_err(|e| e.to_string())?;
        return Ok(());
    }
    Err("package download redirected too often".into())
}

fn transfer(
    url: &str,
    token: &str,
    output: &mut File,
    limit: u64,
) -> Result<(u16, String, String, u64)> {
    let options = proc::Options {
        env: vec![
            ("PATH".into(), proc::HOST_PATH.into()),
            ("LC_ALL".into(), "C".into()),
        ],
        ..Default::default()
    };
    let mut command = proc::command(
        &proc::strings(&[CURL, "--disable", "--config", "-"]),
        &options,
    )?;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{CURL}: {e}"))?;
    let config = curl_config(url, token)?;
    let mut input = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = input.write_all(config.as_bytes());
    });
    let mut stderr = child.stderr.take().unwrap();
    let errors = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = (&mut stderr).take(1 << 20).read_to_end(&mut out);
        out
    });
    let mut stdout = child.stdout.take().unwrap();
    let mut hash = Sha256::new();
    let mut received = 0u64;
    let mut buffer = vec![0u8; 1 << 20];
    let mut failure = None;
    loop {
        if let Err(error) = proc::check_interrupted() {
            failure = Some(error);
            break;
        }
        let n = match stdout.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) => {
                failure = Some(error.to_string());
                break;
            }
        };
        received += n as u64;
        if received > limit {
            failure = Some("package download exceeds its protected size".into());
            break;
        }
        hash.update(&buffer[..n]);
        if let Err(error) = output.write_all(&buffer[..n]) {
            failure = Some(error.to_string());
            break;
        }
    }
    if failure.is_some() {
        proc::signal_process(-(child.id() as i32), proc::SIGKILL);
    }
    drop(stdout);
    let waited = proc::supervise(
        &mut child,
        &proc::Options {
            timeout: Some(Duration::from_secs(30)),
            ..Default::default()
        },
        "curl",
    );
    let _ = writer.join();
    let stderr = String::from_utf8_lossy(&errors.join().unwrap_or_default()).into_owned();
    if let Some(error) = failure {
        return Err(error);
    }
    let status = waited?;
    let (code, target) = status_or_detail(&stderr, token)?;
    require(
        status.success(),
        &format!(
            "package download failed: {}",
            redact(stderr.lines().next().unwrap_or(""), token)
        ),
    )?;
    Ok((code, target, hash.hex(), received))
}

fn status_or_detail(stderr: &str, token: &str) -> Result<(u16, String)> {
    status(stderr).map_err(|e| format!("{e}: {}", redact(stderr, token)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_redirect_cannot_leave_the_package_origin() {
        let package = "https://git.getbusbar.dev/api/v4/projects/3/packages/generic/x/1/image.tar";
        same_origin(package, "https://git.getbusbar.dev/other/path?x=1").unwrap();
        same_origin(package, "https://GIT.getbusbar.dev/other").unwrap();
        for bad in [
            "https://other.invalid/archive",
            "http://git.getbusbar.dev/archive",
            "https://git.getbusbar.dev:444/archive",
            "https://user@git.getbusbar.dev/archive",
            "https://git.getbusbar.dev.evil.invalid/archive",
        ] {
            assert!(same_origin(package, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn credential_is_confined_to_curl_stdin_configuration() {
        let config = curl_config("https://git.getbusbar.dev/a", "glcbt-fixture_token").unwrap();
        assert!(config.contains("header = \"JOB-TOKEN:glcbt-fixture_token\""));
        assert!(config.contains("max-redirs = 0"));
        assert!(config.contains("proto = \"=https\""));
        assert!(curl_config("https://git.getbusbar.dev/a", "bad\"\ntoken").is_err());
        assert!(curl_config("https://git.getbusbar.dev/a b", "t").is_err());
        assert_eq!(
            status("noise\nBUSBAR-CURL 302 https://x/y\n").unwrap(),
            (302, "https://x/y".into())
        );
        assert_eq!(
            status("\nBUSBAR-CURL 200 \n").unwrap(),
            (200, String::new())
        );
        assert!(status("curl: (6) could not resolve").is_err());
    }

    #[test]
    fn diagnostics_are_bounded_and_redact_job_credentials() {
        let message = redact(
            &("prefix".repeat(1000) + "\u{1b}[31m token-secret invalid archive"),
            "token-secret",
        );
        assert!(!message.contains("token-secret"));
        assert!(!message.contains('\u{1b}'));
        assert!(message.contains("[redacted]") && message.ends_with("invalid archive"));
        assert!(message.len() <= 4096);
    }
}
