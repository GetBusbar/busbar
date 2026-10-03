//! `cargo xtask install-sizes [--check]` — measure what you actually install, and write
//! `assets/readme/install.json`.
//!
//! The port of the removed `assets/readme/install-sizes.py`. The README's performance and memory
//! figures come from onthebench.ai (see `cargo xtask readme-assets`). These do NOT: an image size is
//! a registry fact, not a load test, so it is a SEPARATE instrument and carries its own stamp.
//! Folding it into data.json would let one date stand for two measurements taken months apart.
//!
//!   cargo xtask install-sizes            # re-measure from the registries, rewrite install.json
//!   cargo xtask install-sizes --check    # exit 1 if the checked-in file disagrees
//!
//! Compressed layer blobs are summed, which is what a `docker pull` transfers and what the registry
//! stores. Only the manifests are fetched; no image is pulled.
//!
//! One field cannot be measured this way and says so in the file: the size of a `pip install` into a
//! clean virtualenv. It needs a real install on a real machine, so it is carried with the command
//! that produced it and the date it was run, and `--check` deliberately does not re-derive it.
//!
//! THE NETWORK. The script used `urllib` with a 30 s timeout. This shells out to `curl` for the same
//! requests (same URLs, same headers, same timeout; `-L` because `urllib` follows redirects), which
//! adds no dependency. A registry that cannot be reached exits 3 (the tool could not run), never 1
//! (the file disagrees): the script's traceback exit conflated the two.

use crate::ctx::Ctx;
use crate::json_lite::{self, Json, Obj};
use crate::readme_assets::py_float_repr;
use std::process::Command;

const IDX: &str = "application/vnd.oci.image.index.v1+json,\
application/vnd.docker.distribution.manifest.list.v2+json";
const MAN: &str = "application/vnd.oci.image.manifest.v1+json,\
application/vnd.docker.distribution.manifest.v2+json";

/// The generator named in `install.json`'s `_generator` field.
pub const GENERATOR: &str = "cargo xtask install-sizes";

/// (key, registry host, repository, tag, the platform the README compares on)
const IMAGES: &[(&str, &str, &str, &str, &str)] = &[
    (
        "busbar",
        "registry-1.docker.io",
        "getbusbar/busbar",
        "latest",
        "amd64",
    ),
    (
        "litellm",
        "ghcr.io",
        "berriai/litellm",
        "main-latest",
        "amd64",
    ),
];

fn curl(url: &str, headers: &[String]) -> Result<serde_json::Value, String> {
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "-f", "-L", "--max-time", "30"]);
    for h in headers {
        cmd.args(["-H", h]);
    }
    cmd.arg(url);
    let out = cmd
        .output()
        .map_err(|e| format!("could not run curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "GET {url}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("GET {url}: not JSON: {e}"))
}

/// Anonymous pull token. Docker Hub and GHCR use different auth endpoints, same bearer shape.
fn token(host: &str, repo: &str) -> Result<String, String> {
    let url = if host == "ghcr.io" {
        format!("https://ghcr.io/token?scope=repository:{repo}:pull&service=ghcr.io")
    } else {
        format!(
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
        )
    };
    let v = curl(&url, &[])?;
    v.get("token")
        .and_then(|t| t.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("{url}: no `token` in the response"))
}

fn fetch(
    host: &str,
    repo: &str,
    reference: &str,
    tok: &str,
    accept: &str,
) -> Result<serde_json::Value, String> {
    curl(
        &format!("https://{host}/v2/{repo}/manifests/{reference}"),
        &[
            format!("Authorization: Bearer {tok}"),
            format!("Accept: {accept}"),
        ],
    )
}

/// The digest of the `linux/<arch>` entry of a multi-arch index.
fn pick_digest(idx: &serde_json::Value, arch: &str) -> Result<String, String> {
    idx["manifests"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|m| {
            m["platform"]["os"].as_str() == Some("linux")
                && m["platform"]["architecture"].as_str() == Some(arch)
        })
        .and_then(|m| m["digest"].as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("no linux/{arch} manifest in the index"))
}

/// `round(x, 2)`: Python rounds the correctly-rounded decimal expansion, half to even, which is what
/// `{:.2}` prints; parsing that back gives the same float.
fn round2(x: f64) -> f64 {
    format!("{x:.2}").parse().unwrap_or(x)
}

/// The record one image contributes: pure over the layer sizes, so the unit tests pin it.
pub fn image_record(repo: &str, tag: &str, arch: &str, layers: &[u64]) -> Json {
    let total: u64 = layers.iter().sum();
    let mut o = Obj::new();
    o.insert("image", Json::Str(format!("{repo}:{tag}")));
    o.insert("platform", Json::Str(format!("linux/{arch}")));
    o.insert("compressed_bytes", Json::Int(total as i64));
    // BOTH units, spelled correctly, because they differ by 5% and the README quotes one of them.
    // Compressed blobs: what the pull transfers. Not the uncompressed on-disk rootfs.
    o.insert(
        "compressed_mib",
        Json::Float(round2(total as f64 / 1048576.0)),
    );
    o.insert("compressed_mb", Json::Float(round2(total as f64 / 1e6)));
    o.insert("layers", Json::Int(layers.len() as i64));
    Json::Object(o)
}

fn measure(host: &str, repo: &str, tag: &str, arch: &str) -> Result<Json, String> {
    let tok = token(host, repo)?;
    let idx = fetch(host, repo, tag, &tok, &format!("{IDX},{MAN}"))?;
    let man = if idx["manifests"].as_array().is_some_and(|a| !a.is_empty()) {
        // multi-arch index: pick the platform the comparison is stated on
        let digest = pick_digest(&idx, arch)?;
        fetch(host, repo, &digest, &tok, MAN)?
    } else {
        idx
    };
    let mut sizes = Vec::new();
    for l in man["layers"].as_array().ok_or("manifest has no `layers`")? {
        sizes.push(l["size"].as_u64().ok_or("a layer has no integer `size`")?);
    }
    Ok(image_record(repo, tag, arch, &sizes))
}

/// The document the script writes: the measured `images`, and `hand_measured` CARRIED from the
/// previous file (or the empty template when there is none, or it is falsy).
pub fn build_document(images: Json, prev: &Json) -> Json {
    let mut out = Obj::new();
    out.insert("_generator", Json::Str(GENERATOR.into()));
    out.insert("images", images);
    let carried = prev.get("hand_measured");
    out.insert(
        "hand_measured",
        if carried.truthy() {
            carried.clone()
        } else {
            let mut h = Obj::new();
            h.insert("busbar_binary_mib", Json::Null);
            h.insert("litellm_venv_mib", Json::Null);
            h.insert("litellm_venv_packages", Json::Null);
            h.insert(
                "command",
                Json::Str("pip install 'litellm[proxy]' into a clean virtualenv".into()),
            );
            h.insert("measured_at", Json::Null);
            Json::Object(h)
        },
    );
    Json::Object(out)
}

/// `json.dump(doc, fh, indent=1)` plus the separate trailing newline. Python's default is
/// `ensure_ascii=True`, so every non-ASCII character (all of which sit inside strings) becomes
/// `\uXXXX`, an astral one as a surrogate pair.
pub fn render(doc: &Json) -> String {
    let mut out = String::new();
    for c in json_lite::dump_python(doc).chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    out.push('\n');
    out
}

/// Python `==` on decoded JSON: objects ignore key order, `6` equals `6.0`.
fn json_eq(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Int(x), Json::Float(y)) | (Json::Float(y), Json::Int(x)) => (*x as f64) == *y,
        (Json::Float(x), Json::Float(y)) => x == y,
        (Json::Array(x), Json::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_eq(p, q))
        }
        (Json::Object(x), Json::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| json_eq(v, w)))
        }
        _ => a == b,
    }
}

/// Python's `repr` of a decoded value, floats included.
fn repr(v: &Json) -> String {
    match v {
        Json::Float(f) => py_float_repr(*f),
        Json::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Json::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", json_lite::py_repr(k), repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => json_lite::py_repr_json(other),
    }
}

pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    let mut check = false;
    for a in args {
        match a.as_str() {
            "--check" => check = true,
            other => {
                eprintln!("xtask install-sizes: unknown argument `{other}`\nusage: cargo xtask install-sizes [--check]");
                return 2;
            }
        }
    }
    let out_path = cx.root().join("assets").join("readme").join("install.json");
    let prev = if out_path.exists() {
        match std::fs::read_to_string(&out_path)
            .map_err(|e| e.to_string())
            .and_then(|t| json_lite::parse(&t))
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("xtask install-sizes: {}: {e}", out_path.display());
                return 3;
            }
        }
    } else {
        Json::Object(Obj::new())
    };

    let mut images = Obj::new();
    for (key, host, repo, tag, arch) in IMAGES {
        match measure(host, repo, tag, arch) {
            Ok(rec) => images.insert(*key, rec),
            Err(e) => {
                eprintln!("xtask install-sizes: {key}: {e}");
                return 3;
            }
        }
    }
    let images = Json::Object(images);

    if check {
        if !prev.truthy() {
            eprintln!(
                "{} is missing; run: cargo xtask install-sizes",
                out_path.display()
            );
            return 1;
        }
        let prev_images = prev.get("images");
        if !json_eq(prev_images, &images) {
            eprintln!(
                "{} disagrees with the registries; run: cargo xtask install-sizes",
                out_path.display()
            );
            if let Some(o) = images.as_object() {
                for (k, v) in o.iter() {
                    let was = prev_images.get(k);
                    if !json_eq(was, v) {
                        eprintln!("  {k}: {} -> {}", repr(was), repr(v));
                    }
                }
            }
            return 1;
        }
        println!("install.json agrees with the registries");
        return 0;
    }

    let doc = build_document(images.clone(), &prev);
    if let Err(e) = std::fs::write(&out_path, render(&doc)) {
        eprintln!("xtask install-sizes: {}: {e}", out_path.display());
        return 3;
    }
    println!("wrote {}", out_path.display());
    if let Some(o) = images.as_object() {
        for (k, v) in o.iter() {
            println!(
                "  {k}: {} MB across {} layers ({})",
                repr(v.get("compressed_mb")),
                repr(v.get("layers")),
                v.get("platform").as_str().unwrap_or("")
            );
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Json {
        let mut imgs = Obj::new();
        imgs.insert(
            "busbar",
            image_record(
                "getbusbar/busbar",
                "latest",
                "amd64",
                &[1000000, 5000000, 22218],
            ),
        );
        Json::Object(imgs)
    }

    #[test]
    fn record_matches_the_committed_busbar_row() {
        // 6022218 bytes in 3 layers: the checked-in row, computed by the Python.
        let r = image_record(
            "getbusbar/busbar",
            "latest",
            "amd64",
            &[1000000, 5000000, 22218],
        );
        assert_eq!(
            json_lite::dump_python(&r),
            "{\n \"image\": \"getbusbar/busbar:latest\",\n \"platform\": \"linux/amd64\",\n \
             \"compressed_bytes\": 6022218,\n \"compressed_mib\": 5.74,\n \"compressed_mb\": 6.02,\n \
             \"layers\": 3\n}"
        );
    }

    #[test]
    fn rounding_is_pythons() {
        // round(x, 2) values from Python 3.
        assert_eq!(round2(378298760.0 / 1048576.0), 360.77);
        assert_eq!(round2(378298760.0 / 1e6), 378.3);
        assert_eq!(round2(0.125), 0.12);
        assert_eq!(round2(2.675), 2.67);
        assert_eq!(round2(1.005), 1.0);
        assert_eq!(py_float_repr(round2(6000000.0 / 1e6)), "6.0");
        assert_eq!(py_float_repr(round2(1048576.0 / 1048576.0)), "1.0");
    }

    #[test]
    fn document_matches_json_dump_indent_1() {
        let prev = json_lite::parse(
            r#"{"hand_measured":{"note":"n","busbar_binary_mib":12.39,"litellm_venv_mib":558}}"#,
        )
        .unwrap();
        let doc = build_document(sample(), &prev);
        let want = "{\n \"_generator\": \"cargo xtask install-sizes\",\n \"images\": {\n  \"busbar\": {\n   \
            \"image\": \"getbusbar/busbar:latest\",\n   \"platform\": \"linux/amd64\",\n   \
            \"compressed_bytes\": 6022218,\n   \"compressed_mib\": 5.74,\n   \"compressed_mb\": 6.02,\n   \
            \"layers\": 3\n  }\n },\n \"hand_measured\": {\n  \"note\": \"n\",\n  \
            \"busbar_binary_mib\": 12.39,\n  \"litellm_venv_mib\": 558\n }\n}\n";
        assert_eq!(render(&doc), want);
    }

    #[test]
    fn missing_or_falsy_hand_measured_gets_the_template() {
        for prev in ["{}", r#"{"hand_measured":{}}"#, r#"{"hand_measured":null}"#] {
            let doc = build_document(sample(), &json_lite::parse(prev).unwrap());
            let text = render(&doc);
            assert!(text.ends_with(
                " \"hand_measured\": {\n  \"busbar_binary_mib\": null,\n  \"litellm_venv_mib\": null,\n  \
                 \"litellm_venv_packages\": null,\n  \"command\": \"pip install 'litellm[proxy]' into a \
                 clean virtualenv\",\n  \"measured_at\": null\n }\n}\n"
            ), "{text}");
        }
    }

    #[test]
    fn ensure_ascii_escapes_like_python() {
        let doc = Json::Str("é😀".into());
        // json.dumps("é😀") == '"\\u00e9\\ud83d\\ude00"'
        assert_eq!(render(&doc), "\"\\u00e9\\ud83d\\ude00\"\n");
    }

    #[test]
    fn equality_is_pythons() {
        let a = json_lite::parse(r#"{"x":6,"y":[1,2]}"#).unwrap();
        let b = json_lite::parse(r#"{"y":[1,2],"x":6.0}"#).unwrap();
        assert!(json_eq(&a, &b));
        assert!(!json_eq(
            &a,
            &json_lite::parse(r#"{"x":6,"y":[1,3]}"#).unwrap()
        ));
        assert_eq!(
            repr(&json_lite::parse(r#"{"a":6.0,"b":null}"#).unwrap()),
            "{'a': 6.0, 'b': None}"
        );
    }

    #[test]
    fn index_platform_pick() {
        let idx: serde_json::Value = serde_json::from_str(
            r#"{"manifests":[{"digest":"sha256:a","platform":{"os":"linux","architecture":"arm64"}},
                {"digest":"sha256:b","platform":{"os":"linux","architecture":"amd64"}}]}"#,
        )
        .unwrap();
        assert_eq!(pick_digest(&idx, "amd64").unwrap(), "sha256:b");
        assert!(pick_digest(&idx, "s390x").is_err());
    }
}
