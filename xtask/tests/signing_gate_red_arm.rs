//! scripts/signing-gate.sh's RED arm ("planted: allow_unsigned"), run as committed against a stub
//! busbar whose loader verdicts the test chooses. The gate's own builds are stubbed (a `cargo` on
//! PATH that builds nothing, a `busbar` and a `busbar-plugin-pack` in the target dir it reads), so
//! what is judged is the gate's LOGIC: which verdicts it calls a pass.
//!
//! THE HOLE THIS HOLDS SHUT: the RED arm re-judged the unsigned arm under
//! `plugins.trust.allow_unsigned: true` and passed whenever that arm FAILED, never checking that the
//! unsigned tarball actually LOADED there. A plugin the loader refuses under allow_unsigned for
//! another reason (hook-webrequest: an egress-class refusal) failed the unsigned arm too, so the RED
//! arm passed while proving nothing about signing (BUSBAR-1.6.0.md Law 0: an instrument that cannot
//! produce a NO is not a check; Law 8: every gate owes a positive control; Law 10: a proof must not
//! point at something that never runs). The arm must assert the outcome it plants: the unsigned
//! tarball LOADS under allow_unsigned, and is refused for the signing reason without it. Any other
//! refusal makes the arm itself red.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The committed gate, compiled in: this test is rebuilt whenever the gate changes.
const GATE: &str = include_str!("../../scripts/signing-gate.sh");

/// `busbar-plugin-pack`, stubbed: `keygen` prints a fresh pair; `pack` writes a real tarball (the
/// gate unpacks and repacks it for its tamper cases) whose manifest carries the library's sha256 and,
/// as its "signature", the signing key (none when packed `--allow-unsigned` with no key).
const PACK: &str = r#"#!/usr/bin/env python3
import hashlib, io, json, os, secrets, sys, tarfile
a = sys.argv[1:]
if a[:1] == ["keygen"]:
    print("private key: " + secrets.token_hex(32))
    print("public key:  " + secrets.token_hex(32))
    sys.exit(0)
assert a[:1] == ["pack"], a
opts, unsigned, i = {}, False, 1
while i < len(a):
    if a[i] == "--allow-unsigned":
        unsigned, i = True, i + 1
    else:
        opts[a[i]], i = a[i + 1], i + 2
lib = open(opts["--lib"], "rb").read()
key = os.environ.get("BUSBAR_SIGN_KEY") or None
if key is None and not unsigned:
    sys.exit("pack: no signing key and not --allow-unsigned")
manifest = json.dumps({
    "name": opts["--name"], "alias": opts["--alias"], "kind": opts["--kind"],
    "version": "1.0.0", "sha256": hashlib.sha256(lib).hexdigest(), "signature": key,
}).encode()
with tarfile.open(opts["--out"], "w:gz") as t:
    for name, data in (("manifest.json", manifest), ("lib.so", lib)):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
"#;

/// `busbar`, stubbed: `--validate` loads every tarball in the config's plugins dir and refuses as the
/// loader does (integrity, a missing signature without allow_unsigned, a signature by another key or
/// over an edited manifest). `STUB_UNDER_ALLOW` picks what it does with an UNSIGNED tarball under
/// allow_unsigned: `loads` (the honest loader), `egress` (refused for another reason, as
/// hook-webrequest is), `ignored` (refused for the missing signature regardless).
const BUSBAR: &str = r#"#!/usr/bin/env python3
import glob, hashlib, json, os, re, sys, tarfile
if sys.argv[1:] == ["--version"]:
    print("busbar 1.6.0")
    sys.exit(0)
assert sys.argv[1:] == ["--validate"], sys.argv
cfg = open(os.environ["BUSBAR_CONFIG"]).read()
allow = re.search(r"allow_unsigned:\s*true", cfg) is not None
plugins = re.search(r"dir: '([^']*)'", cfg).group(1)
refs = [m for m in re.findall(r"module: (\S+)", cfg) if m != "memory"]
mode = os.environ["STUB_UNDER_ALLOW"]
loaded = set()
for tb in sorted(glob.glob(os.path.join(plugins, "*.tar.gz"))):
    f = os.path.basename(tb)
    with tarfile.open(tb) as t:
        files = {m.name: t.extractfile(m).read() for m in t.getmembers()}
    m = json.loads(files["manifest.json"])
    def refuse(why):
        print(f"error: hook plugin '{m['name']}' is present ({f}) but it was not loaded: {why}")
        sys.exit(1)
    if hashlib.sha256(files["lib.so"]).hexdigest() != m["sha256"]:
        refuse("library bytes do not match the manifest sha256 (integrity failure)")
    if m["signature"] is None:
        if not allow:
            refuse("manifest carries no signature (plugins.trust.allow_unsigned is off)")
        if mode == "egress":
            refuse("an unsigned plugin may not declare an egress class")
        if mode == "ignored":
            refuse("manifest carries no signature")
    elif m["signature"] != os.environ["BUSBAR_GATE_SIGN_KEY"] or m["version"] != "1.0.0":
        refuse("first-party signature failed")
    loaded.add(m["name"])
for r in refs:
    if r not in loaded:
        print(f"error: hooks.signing-gate-ref names module '{r}', which no plugin provides")
        sys.exit(1)
print(f"plugins: {len(loaded)} validated, 0 skipped")
"#;

struct Run {
    ok: bool,
    log: String,
}

fn write_exec(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "signing-gate-red-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The committed gate over a hook plugin no linked row answers (the exit-code mode
/// hook-webrequest runs in), against the stub loader in `mode`.
fn gate(mode: &str) -> Run {
    let root = scratch(mode);
    let busbar = root.join("busbar");
    write_exec(&busbar.join("scripts/signing-gate.sh"), GATE);
    std::fs::create_dir_all(busbar.join("crates/plugin-loader/src")).unwrap();
    std::fs::write(busbar.join("crates/plugin-loader/src/sign.rs"), "").unwrap();
    let target = root.join("target");
    write_exec(&target.join("release/busbar-plugin-pack"), PACK);
    write_exec(&target.join("release/busbar"), BUSBAR);
    let bin = root.join("bin");
    write_exec(&bin.join("cargo"), "#!/bin/sh\nexit 0\n");
    let lib = root.join("lib/libbusbar_hook_fixture_plugin.so");
    std::fs::create_dir_all(lib.parent().unwrap()).unwrap();
    std::fs::write(&lib, vec![0x5au8; 4096]).unwrap();

    let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let out = Command::new("bash")
        .arg(busbar.join("scripts/signing-gate.sh"))
        .args([
            busbar.as_os_str(),
            "busbar-hook-fixture-plugin".as_ref(),
            "hook".as_ref(),
            "fixture".as_ref(),
            lib.as_os_str(),
            "busbar-hook-fixture".as_ref(),
        ])
        .env("PATH", path)
        .env("CARGO_TARGET_DIR", target)
        .env("BUSBAR_GATE_SIGN_KEY", "a".repeat(64))
        .env("BUSBAR_GATE_PUBKEY", "b".repeat(64))
        .env_remove("BUSBAR_SIGN_KEY")
        .env_remove("MOCK_KEY")
        .env("STUB_UNDER_ALLOW", mode)
        .output()
        .expect("bash runs the gate");
    let run = Run {
        ok: out.status.success(),
        log: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    };
    let _ = std::fs::remove_dir_all(&root);
    run
}

/// THE POSITIVE CONTROL: with an honest loader (the unsigned tarball loads under allow_unsigned and is
/// refused for its missing signature without it) every arm, the RED arm included, passes.
#[test]
fn an_honest_loader_passes_every_arm() {
    let r = gate("loads");
    assert!(r.ok, "the gate refused an honest loader:\n{}", r.log);
    assert!(
        r.log.contains("ALL SIGNING ASSERTIONS PASSED"),
        "the gate did not reach its verdict:\n{}",
        r.log
    );
}

/// THE PLANTED CASE: under allow_unsigned the loader refuses the unsigned tarball for a reason that
/// is not signing (an egress class, as for hook-webrequest). The RED arm planted a LOAD and got a
/// refusal, so the arm is red, and the refusal is shown.
#[test]
fn red_the_planted_allow_unsigned_arm_fails_when_the_unsigned_tarball_does_not_load() {
    let r = gate("egress");
    assert!(
        !r.ok,
        "an unsigned tarball refused under allow_unsigned for an egress class passed the RED arm:\n{}",
        r.log
    );
    assert!(
        r.log.contains("FAIL [") && r.log.contains("may not declare an egress class"),
        "the gate went red without naming the arm and the refusal:\n{}",
        r.log
    );
}

/// And a loader that ignores allow_unsigned (the unsigned tarball still refused for its signature)
/// is red too: the plant did not take.
#[test]
fn red_the_planted_arm_fails_when_allow_unsigned_changes_nothing() {
    let r = gate("ignored");
    assert!(
        !r.ok,
        "allow_unsigned changed nothing and the gate passed:\n{}",
        r.log
    );
}
