//! The signed shipping oracle, extracted from the pinned native image and
//! verified against the protected release key (former `native_oracle.prepare`).
//! Candidate builds receive no release credentials.
use super::Q;
use super::sp::{self, Dict, R, Spec, at, need, value_error, violation};
use crate::confine::digest;
use crate::json::{Value, object};
use std::path::Path;

const IMAGE_TOOLS: &str = "/opt/busbar-native/oracle";

/// `base64.b64decode(text, validate=True)`.
pub fn b64decode(text: &str) -> R<Vec<u8>> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let bytes = text.as_bytes();
    let padding = bytes.iter().rev().take_while(|c| **c == b'=').count();
    let body = &bytes[..bytes.len() - padding];
    if body.iter().any(|c| value(*c).is_none()) || padding > 2 {
        return Err(value_error("Only base64 data is allowed"));
    }
    if !bytes.len().is_multiple_of(4) || (padding > 0 && body.len() % 4 + padding != 4) {
        return Err(value_error("Incorrect padding"));
    }
    let mut out = Vec::new();
    let mut accumulator = 0u32;
    let mut bits = 0;
    for c in body {
        accumulator = (accumulator << 6) | u32::from(value(*c).unwrap());
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// `verify(path, pin, arch, evidence)`.
pub fn verify(path: &Path, pin: &Value, arch: &str, evidence: &Path) -> R<String> {
    let row = at(at(pin, "platforms")?, arch)?;
    let actual = digest(path)?;
    need(
        Some(actual.as_str()) == row.at("sha256").as_str(),
        "installed oracle judge digest differs from protected pin",
    )?;
    sp::mkdirs(evidence, false)?;
    let key = evidence.join("release-key.pem");
    let message = evidence.join("message");
    let signature = evidence.join("signature");
    sp::write(&key, sp::at_str(pin, "release_key_pem")?)?;
    sp::write(
        &message,
        format!("{}\n{actual}\n", sp::at_str(row, "filename")?),
    )?;
    sp::write(&signature, b64decode(sp::at_str(row, "signature")?)?)?;
    let result = sp::run(
        Spec::new(sp::strings(&[
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            &sp::text(&key),
            "-rawin",
            "-in",
            &sp::text(&message),
            "-sigfile",
            &sp::text(&signature),
        ]))
        .capture()
        .timeout(30),
    )?;
    need(
        result.code == 0,
        "oracle judge signature does not match the protected release key",
    )?;
    Ok(actual)
}

pub fn prepare(q: &mut Q) -> R<()> {
    let pin = sp::read_json(&q.trusted.join("ci/native-oracle.json"))?;
    let arch = match std::env::consts::ARCH {
        "amd64" => "x86_64",
        "arm64" => "aarch64",
        other => other,
    };
    if !cfg!(target_os = "linux") || at(&pin, "platforms")?.get(arch).is_none() {
        return Err(violation(
            "no protected oracle judge for this native platform",
        ));
    }
    let row = at(at(&pin, "platforms")?, arch)?.clone();
    let bin = sp::at_str(&pin, "bin")?.to_owned();
    // Extract fixed signed bytes from the already present immutable image.
    // The container is never started and the candidate never sees its socket.
    let directory = q.control.join("oracle");
    sp::mkdir(&directory, 0o755, false)?;
    let judge = directory.join(&bin);
    let name = format!("busbar-oracle-input-{}", sp::uuid_hex());
    let execution = q.execution();
    let image = execution.image().to_owned();
    let extracted = (|| -> R<()> {
        let created = execution.client(&sp::strings(&[
            "create",
            "--pull=never",
            "--name",
            &name,
            "--entrypoint",
            "/bin/false",
            &image,
        ]))?;
        need(
            created.code == 0,
            "pinned image oracle extraction could not create a container",
        )?;
        let inside = format!("{name}:{IMAGE_TOOLS}/{}/{bin}", sp::at_str(&row, "sha256")?);
        let copied = execution.client(&["cp".to_owned(), inside, sp::text(&judge)])?;
        need(
            copied.code == 0,
            "signed oracle is absent from the pinned native image",
        )
    })();
    let disposed = (|| -> R<()> {
        execution.client(&sp::strings(&["rm", "--force", &name]))?;
        let filter = format!("name=^/{name}$");
        let absent = execution.client(&sp::strings(&[
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            &filter,
        ]))?;
        need(
            absent.code == 0 && absent.text().trim().is_empty(),
            "oracle extraction container disposal was not confirmed",
        )
    })();
    disposed?;
    extracted?;
    need(
        !sp::is_symlink(&judge) && judge.is_file(),
        "image oracle is not a regular file",
    )?;
    sp::chmod(&judge, 0o555)?;
    q.execution().extra_readonly.push(directory);
    let actual = verify(&judge, &pin, arch, &q.evidence.join("oracle-identity"))?;
    let platforms = at(&pin, "platforms")?;
    let mut values = Dict::default();
    values.set(
        "BUSBAR_ORACLE_RELEASE_REPO",
        sp::at_str(&pin, "repository")?,
    );
    values.set("BUSBAR_ORACLE_RELEASE_REF", sp::at_str(&pin, "source")?);
    values.set(
        "BUSBAR_ORACLE_SHA256_LINUX_X86_64",
        sp::at_str(at(platforms, "x86_64")?, "sha256")?,
    );
    values.set(
        "BUSBAR_ORACLE_SHA256_LINUX_AARCH64",
        sp::at_str(at(platforms, "aarch64")?, "sha256")?,
    );
    values.set("BUSBAR_ORACLE_CRATE", sp::at_str(&pin, "crate")?);
    values.set("BUSBAR_ORACLE_BIN", bin.as_str());
    values.set("BUSBAR_ORACLE_JUDGE_PATH", sp::text(&judge));
    q.env.update(&values);
    q.execution().oracle_inputs = values;
    q.receipt.set(
        "oracle_judge",
        object([
            ("source", at(&pin, "source")?.clone()),
            ("sha256", actual.into()),
            ("canonical_asset", at(&row, "canonical_asset")?.clone()),
            ("signature_verified", true.into()),
        ]),
    );
    q.save()?;
    q.run_timeout(
        "oracle-judge-available",
        vec![sp::text(&judge), "--help".into()],
        30,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_decode_strictly() {
        assert_eq!(b64decode("Z2l0bGFi").unwrap(), b"gitlab");
        assert_eq!(b64decode("YWI=").unwrap(), b"ab");
        assert_eq!(b64decode("YQ==").unwrap(), b"a");
        assert_eq!(b64decode("YWI").unwrap_err().message, "Incorrect padding");
        assert_eq!(
            b64decode("Y W=").unwrap_err().message,
            "Only base64 data is allowed"
        );
    }
}
