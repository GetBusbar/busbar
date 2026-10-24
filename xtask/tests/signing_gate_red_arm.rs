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
/// as its "signature", the signing key (none when packed `--allow-unsigned` with no key). When
/// `STUB_STATEMENT` is set the manifest states it (the hex Statement rendering the real packer reads
/// out of the library), as a plugin with declared needs does.
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
    **({"statement": os.environ["STUB_STATEMENT"]} if os.environ.get("STUB_STATEMENT") else {}),
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
/// hook-webrequest is), `ignored` (refused for the missing signature regardless), `grant` (refused
/// for the egress-class grant, in the loader's own words, naming the need `STUB_GRANT_NEED` gives as
/// `<transport> <class>`, under the code `STUB_GRANT_CODE` gives (default `BUSBAR-6009`): what the real loader does to an unsigned plugin whose Statement declares a
/// need in a first-party egress class), `other` (refused for a reason that is neither signing nor
/// the grant).
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
        if mode == "grant":
            transport, klass = os.environ["STUB_GRANT_NEED"].split()
            code = os.environ.get("STUB_GRANT_CODE", "BUSBAR-6009")
            print(f"[error] {code}: plugin '{m['name']}' is present ({f}) but was not loaded: "
                  f"plugin '{m['name']}' declares a `{transport}` need in the `{klass}` egress "
                  "class, which the host grants to a first-party plugin only")
            sys.exit(1)
        if mode == "other":
            print(f"[error] BUSBAR-6009: plugin '{m['name']}' is present ({f}) but was not loaded: "
                  f"plugin '{m['name']}' states a version its manifest does not carry")
            sys.exit(1)
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
    gate_with(mode, &[])
}

/// [`gate`], with the stub's environment extended by `env` (the fixture's Statement, the need the
/// stub loader's grant refusal names).
fn gate_with(mode: &str, env: &[(&str, String)]) -> Run {
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
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
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

// ── a plugin whose Statement declares a need in a first-party egress class ─────────────────────────
//
// THE BUG THESE HOLD: the loader admits an unsigned plugin under allow_unsigned, then refuses it at the
// egress-class grant when its Statement declares a need in a class the host grants a first-party
// plugin only (`registry.rs` phase 2b, `sign::egress_grant`: provider, loopback-allowed). Under the
// plant such a plugin can never LOAD, and an arm that demands a load can never pass for it. The arm
// must instead assert, from the plugin's own declared needs, that the signing refusal is gone and the
// grant refusal is the ONLY one, word for word; any other refusal stays red, so the arm still cannot
// be satisfied by an unrelated refusal. `operator-infrastructure` is any trusted plugin's
// (`BUSBAR-1.6.0.md` §5, l.604-613), so a networked auth plugin declaring it must LOAD under the plant.

/// The `operator-infrastructure` egress class (`busbar_contract::abi::host::conn::connector`).
const EGRESS_OPERATOR_INFRASTRUCTURE: u32 = 2;
/// The `loopback-allowed` egress class, a first-party grant.
const EGRESS_LOOPBACK_ALLOWED: u32 = 4;
/// The connector's default class, which any trusted plugin is granted.
const EGRESS_DEFAULT: u32 = 0;

/// A Statement's canonical rendering (`busbar_contract::abi::mechanism::rendering`'s format), hex,
/// stating `needs` as `(egress_class, transport)` and nothing else of note.
fn rendering(name: &str, needs: &[(u32, &str)]) -> String {
    fn u32le(o: &mut Vec<u8>, v: u32) {
        o.extend_from_slice(&v.to_le_bytes());
    }
    fn str_(o: &mut Vec<u8>, s: &str) {
        u32le(o, u32::try_from(s.len()).unwrap());
        o.extend_from_slice(s.as_bytes());
    }
    fn blob(o: &mut Vec<u8>) {
        u32le(o, 0); // fmt
        u32le(o, 0); // flags
        u32le(o, 0); // length
    }
    let mut o = b"BBSTMT01".to_vec();
    for v in [1u32, 3, 1, 1] {
        u32le(&mut o, v); // mechanism, kind, kind_abi, max_inflight
    }
    str_(&mut o, name);
    str_(&mut o, "1.0.0");
    u32le(&mut o, 0); // families
    u32le(&mut o, 0); // diag_ids
    u32le(&mut o, 0); // kind_tail
    blob(&mut o); // extensions
    u32le(&mut o, 0); // secret_refs
    blob(&mut o); // settings_schema
    o.extend_from_slice(&0u64.to_le_bytes()); // marks
    u32le(&mut o, 0); // mark_words
    u32le(&mut o, 0); // rewrites
    u32le(&mut o, 0); // sections
    u32le(&mut o, u32::try_from(needs.len()).unwrap());
    for (class, transport) in needs {
        u32le(&mut o, 1); // direction: outbound
        u32le(&mut o, *class);
        str_(&mut o, transport);
        for _ in 0..3 {
            str_(&mut o, ""); // auth, target_from, trust_from
        }
        blob(&mut o); // details
        o.extend_from_slice(&0u64.to_le_bytes()); // timeout_ms
    }
    str_(&mut o, ""); // target_from
    str_(&mut o, ""); // trust_from
    u32le(&mut o, 0); // answers
    u32le(&mut o, 0); // claims
    o.iter().map(|b| format!("{b:02x}")).collect()
}

/// The fixture's Statement: a default-class need, an operator-infrastructure `http` need (any trusted
/// plugin's), then a loopback-allowed `tcp` need, the first need in a first-party class and so the
/// one the loader's refusal names.
fn first_party_class_fixture() -> String {
    rendering(
        "busbar-hook-fixture",
        &[
            (EGRESS_DEFAULT, "http"),
            (EGRESS_OPERATOR_INFRASTRUCTURE, "http"),
            (EGRESS_LOOPBACK_ALLOWED, "tcp"),
        ],
    )
}

/// A Statement whose only non-default need is operator-infrastructure: no first-party grant.
fn operator_infrastructure_fixture() -> String {
    rendering(
        "busbar-hook-fixture",
        &[
            (EGRESS_DEFAULT, "http"),
            (EGRESS_OPERATOR_INFRASTRUCTURE, "tcp"),
        ],
    )
}

/// THE GREEN TWIN: the fixture declares a loopback-allowed need, and the loader refuses its
/// unsigned tarball under allow_unsigned for exactly that grant, in its own words, and for nothing
/// else. Every arm passes. Before the fix this was the bug: the planted arm demanded a load the
/// loader can never give such a plugin, and the gate was red for every networked plugin.
#[test]
fn a_plugin_with_a_first_party_class_need_passes_when_the_grant_is_its_only_refusal() {
    let r = gate_with(
        "grant",
        &[
            ("STUB_STATEMENT", first_party_class_fixture()),
            ("STUB_GRANT_NEED", "tcp loopback-allowed".to_string()),
        ],
    );
    assert!(
        r.ok,
        "the gate refused a plugin whose only refusal under allow_unsigned is the egress-class grant \
         its own Statement declares:\n{}",
        r.log
    );
    assert!(
        r.log.contains("ALL SIGNING ASSERTIONS PASSED"),
        "the gate did not reach its verdict:\n{}",
        r.log
    );
}

/// RED: the same fixture, refused under allow_unsigned for a reason that is not the grant. The arm
/// is red: a declared first-party-class need excuses the grant refusal and nothing else.
#[test]
fn red_a_plugin_with_a_first_party_class_need_refused_for_another_reason_fails() {
    let r = gate_with("other", &[("STUB_STATEMENT", first_party_class_fixture())]);
    assert!(
        !r.ok,
        "a plugin refused under allow_unsigned for a reason that is not its egress-class grant \
         passed the planted arm:\n{}",
        r.log
    );
    assert!(
        r.log.contains("FAIL [")
            && r.log
                .contains("states a version its manifest does not carry"),
        "the gate went red without naming the arm and the refusal:\n{}",
        r.log
    );
}

/// RED: the same fixture, refused for an egress-class grant that is not the one it declares (the
/// refusal names its `http` need in the loopback-allowed class; the first first-party need it
/// declares is `tcp`). The refusal is matched word for word against the declared need, not by shape.
#[test]
fn red_a_grant_refusal_naming_a_need_the_plugin_does_not_declare_fails() {
    let r = gate_with(
        "grant",
        &[
            ("STUB_STATEMENT", first_party_class_fixture()),
            ("STUB_GRANT_NEED", "http loopback-allowed".to_string()),
        ],
    );
    assert!(
        !r.ok,
        "a grant refusal naming a need the plugin's Statement does not declare passed the planted \
         arm:\n{}",
        r.log
    );
}

/// RED: a plugin that declares NO first-party need, refused at the grant all the same, is red: the
/// arm reads the class from the plugin's declared needs, never from the refusal it is judging.
#[test]
fn red_a_grant_refusal_for_a_plugin_declaring_no_first_party_need_fails() {
    let r = gate_with(
        "grant",
        &[
            (
                "STUB_STATEMENT",
                rendering("busbar-hook-fixture", &[(EGRESS_DEFAULT, "http")]),
            ),
            ("STUB_GRANT_NEED", "http loopback-allowed".to_string()),
        ],
    );
    assert!(
        !r.ok,
        "a plugin declaring no first-party need passed the planted arm on a grant refusal:\n{}",
        r.log
    );
}

/// RED: the same fixture, refused at the grant for its declared `tcp` need but in a class it does not
/// declare that need in. The class in the loader's refusal must be the declared one.
#[test]
fn red_a_grant_refusal_naming_another_egress_class_fails() {
    let r = gate_with(
        "grant",
        &[
            ("STUB_STATEMENT", first_party_class_fixture()),
            ("STUB_GRANT_NEED", "tcp provider".to_string()),
        ],
    );
    assert!(
        !r.ok,
        "a grant refusal naming an egress class the plugin does not declare passed the planted \
         arm:\n{}",
        r.log
    );
}

/// RED: the same fixture, refused at the grant in the loader's words but under a code that is not
/// BUSBAR-6009 (`--validate`'s plugin pre-flight). The code is asserted with the class.
#[test]
fn red_a_grant_refusal_under_another_code_fails() {
    let r = gate_with(
        "grant",
        &[
            ("STUB_STATEMENT", first_party_class_fixture()),
            ("STUB_GRANT_NEED", "tcp loopback-allowed".to_string()),
            ("STUB_GRANT_CODE", "BUSBAR-6001".to_string()),
        ],
    );
    assert!(
        !r.ok,
        "a grant refusal under a code that is not BUSBAR-6009 passed the planted arm:\n{}",
        r.log
    );
}

/// RED (`BUSBAR-1.6.0.md` §5 egress-class table, l.604-613): a plugin whose only non-default need is
/// `operator-infrastructure`, refused at the grant under allow_unsigned, is red. That class is any
/// trusted plugin's, so the grant is not a refusal the planted arm may excuse for it: the unsigned
/// oidc and ldap modules load under allow_unsigned, as 1.5.5 loaded them.
#[test]
fn red_a_grant_refusal_for_an_operator_infrastructure_need_fails() {
    let r = gate_with(
        "grant",
        &[
            ("STUB_STATEMENT", operator_infrastructure_fixture()),
            ("STUB_GRANT_NEED", "tcp operator-infrastructure".to_string()),
        ],
    );
    assert!(
        !r.ok,
        "an operator-infrastructure plugin refused at the egress grant passed the planted arm:\n{}",
        r.log
    );
}

/// GREEN TWIN: the same operator-infrastructure plugin LOADS unsigned under allow_unsigned, and every
/// arm passes, the planted one judged as the load it is.
#[test]
fn an_operator_infrastructure_plugin_that_loads_under_the_plant_passes() {
    let r = gate_with(
        "loads",
        &[("STUB_STATEMENT", operator_infrastructure_fixture())],
    );
    assert!(
        r.ok,
        "the gate refused an operator-infrastructure plugin that loads under allow_unsigned:\n{}",
        r.log
    );
    assert!(
        r.log.contains("ALL SIGNING ASSERTIONS PASSED"),
        "the gate did not reach its verdict:\n{}",
        r.log
    );
}
