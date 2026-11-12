//! Every Python program the native step runner still launches, in one place.
//!
//! None of these is controller logic; each is a recorded step whose argv is
//! part of the receipt and therefore unchanged:
//! * the Python tooling regression steps — the trusted test suites of the
//!   tooling that is still Python (owner admission/retained-evidence readers,
//!   the in-container entry, the isolation diagnostic, CI bootstrap contracts,
//!   toolchain image/seed/probes, conformance capabilities, confined conformance
//!   tools); `architecture-regressions` before them is the controller's own
//!   Rust test suite ([`super::controller_regressions`]);
//! * `development-artifact-evidence` — `development_artifact.py finalize`, whose
//!   deterministic gzip archive bytes are CPython zlib output a std-only port
//!   cannot reproduce byte-for-byte;
//! * candidate-side programs run inside the pinned image (`final-binary`
//!   capture, the trusted product image producer, release engineering, Sigstore observation, the C schema driver,
//!   the conformance runtime preflight and the TSan runtime controls).
use super::sp;
use std::path::Path;

/// `sys.executable` of the former runner, which the bootstrap launched as
/// `/usr/bin/python3`.
pub const PYTHON: &str = "/usr/bin/python3";
const PY: &str = "python3";

fn t(path: &Path) -> String {
    sp::text(path)
}

/// The fixed Python tooling regression suites, in their former order (after
/// the controller's own `architecture-regressions`).
pub fn regressions(trusted: &Path) -> Vec<(&'static str, Vec<String>)> {
    let discover = |directory: &str| {
        vec![
            PYTHON.to_owned(),
            "-m".into(),
            "unittest".into(),
            "discover".into(),
            "-s".into(),
            t(&trusted.join(directory)),
            "-p".into(),
            "test_*.py".into(),
        ]
    };
    let isolated = |relative: &str| {
        vec![
            PYTHON.to_owned(),
            "-B".into(),
            "-I".into(),
            t(&trusted.join(relative)),
        ]
    };
    vec![
        (
            "architecture-tooling-regressions",
            discover("scripts/architecture"),
        ),
        (
            "toolchain-regressions",
            discover("scripts/architecture/toolchain"),
        ),
        (
            "conformance-capability-regressions",
            isolated("testing/conformance/test_capabilities.py"),
        ),
        (
            "conformance-confined-tools-regressions",
            isolated("testing/h2-conformance/test_confined_tools.py"),
        ),
    ]
}

/// `product-image-<repo>` (trusted image producer only): the trusted
/// product-inputs script's one dev-profile image build for a single product,
/// inside the pinned image like the consumer's `scripts/ci-product-inputs.sh`.
pub fn product_image(
    trusted: &Path,
    root: &Path,
    target: &Path,
    cache: &str,
    repo: &str,
) -> Vec<String> {
    vec![
        PY.to_owned(),
        t(&trusted.join("scripts/architecture/product_artifacts.py")),
        "--root".into(),
        t(root),
        "--target".into(),
        t(target),
        "--cache".into(),
        cache.to_owned(),
        "--image-only".into(),
        repo.to_owned(),
    ]
}

/// Whether `argv` is exactly the shape [`product_image`] builds.
pub fn is_product_image(argv: &[String]) -> bool {
    argv.len() >= 2
        && argv[0] == PY
        && argv[1].ends_with("/scripts/architecture/product_artifacts.py")
        && argv.iter().any(|a| a == "--image-only")
}

/// `final-binary`: the candidate build under the capture recorder.
pub fn development_artifact_capture(
    trusted: &Path,
    directory: &Path,
    build: &[String],
) -> Vec<String> {
    let mut command = vec![
        PY.to_owned(),
        "-I".into(),
        t(&trusted.join("scripts/release/development_artifact.py")),
        "capture".into(),
        "--directory".into(),
        t(directory),
        "--".into(),
    ];
    command.extend(build.iter().cloned());
    command
}

#[allow(clippy::too_many_arguments)]
pub fn development_artifact_finalize(
    trusted: &Path,
    directory: &Path,
    binary: &Path,
    source: &str,
    policy: &str,
    sdk: &str,
    vector: &Path,
    compiler_output: &Path,
    command_json: &str,
    retention_policy_sha256: &str,
) -> Vec<String> {
    vec![
        PYTHON.to_owned(),
        "-I".into(),
        t(&trusted.join("scripts/release/development_artifact.py")),
        "finalize".into(),
        "--directory".into(),
        t(directory),
        "--binary".into(),
        t(binary),
        "--source".into(),
        source.into(),
        "--policy".into(),
        policy.into(),
        "--sdk".into(),
        sdk.into(),
        "--vector".into(),
        t(vector),
        "--package".into(),
        "busbar-default".into(),
        "--compiler-output".into(),
        t(compiler_output),
        "--command-json".into(),
        command_json.into(),
        "--retention-policy-sha256".into(),
        retention_policy_sha256.into(),
    ]
}

pub fn release_engineering(
    trusted: &Path,
    source: &str,
    policy: &str,
    report: &Path,
) -> Vec<String> {
    vec![
        PY.to_owned(),
        "-I".into(),
        t(&trusted.join("scripts/release/development_checks.py")),
        "--source".into(),
        source.into(),
        "--policy".into(),
        policy.into(),
        "--output".into(),
        t(report),
    ]
}

pub fn sigstore(root: &Path, development: bool) -> Vec<String> {
    let mut command = vec![
        PY.to_owned(),
        "-I".into(),
        t(&root.join("testing/conformance/sigstore.py")),
    ];
    if !development {
        command.push("--require".into());
    }
    command
}

pub fn c_schema(driver: &Path, schema: &Path) -> Vec<String> {
    vec![PY.to_owned(), t(driver), t(schema)]
}

/// Fixed-source runtime check inside the exact candidate boundary.
pub const CONFORMANCE_PREFLIGHT: &str = "import subprocess,sys,yaml
assert sys.version_info[:2] == (3,11)
assert yaml.__version__ == '6.0.3'
assert subprocess.check_output(['cargo','--version'],text=True).startswith('cargo 1.98.0 ')
assert subprocess.check_output(['node','--version'],text=True).strip() == 'v22.23.3'
print('pinned offline conformance runtime available')
";

pub const BASELINE_PERSONALITY_CONTROL: &str = "import ctypes,errno,json
libc=ctypes.CDLL(None,use_errno=True)
libc.personality.argtypes=[ctypes.c_ulong]
libc.personality.restype=ctypes.c_int
before=libc.personality(0xffffffff)
ctypes.set_errno(0)
result=libc.personality(262144)
error=ctypes.get_errno()
after=libc.personality(0xffffffff)
if (before,result,error,after)!=(0,-1,errno.EPERM,0):
 raise RuntimeError('baseline personality denial differs: '+repr((before,result,error,after)))
print(json.dumps({'argument':262144,'before':before,'result':result,'errno':error,'after':after}))
";

/// The confinement configuration field naming the pinned image interpreter.
pub const INTERPRETER_KEY: &str = "python";

/// The base interpreter an approved offline Python runtime must extend.
pub const BASE_INTERPRETER: &str = "/usr/bin/python3";

/// The in-image interpreter the sanitizer denial witness runs.
pub const IMAGE_PYTHON: &str = "/usr/bin/python3";

/// The sanitizer denial witness, parameterized by the probe work directory
/// exactly like the former `%r` interpolation.
pub fn denial_witness(work: &Path) -> String {
    format!(
        "import ctypes,errno,json,os,pathlib,socket,sys
r=pathlib.Path({})
libc=ctypes.CDLL(None,use_errno=True)
libc.personality.argtypes=[ctypes.c_ulong]
libc.personality.restype=ctypes.c_int
before=libc.personality(0xffffffff)
if before == 0:
 assert libc.personality(262144) == 0
 os.execv(sys.executable,[sys.executable,'-c',sys.argv[1],sys.argv[1]])
assert before == 262144
assert libc.personality(262144 | 0x0400000) == -1 and ctypes.get_errno() == errno.EPERM
assert os.geteuid()!=0
status=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert all(int(status[name].strip(),16)==0 for name in ['CapEff','CapPrm','CapBnd'])
assert status['NoNewPrivs'].strip()=='1' and status['Seccomp'].strip()=='2'
assert not (r/'control/secret').exists()
assert not pathlib.Path('/var/run/docker.sock').exists()
assert not any(k in os.environ for k in ['CI_JOB_TOKEN','AWS_SECRET_ACCESS_KEY','GOOGLE_APPLICATION_CREDENTIALS'])
for p in [r/'harness/immutable',r/'trusted/created',r/'checkout/created',pathlib.Path('/etc/created')]:
 try:p.write_text('BAD')
 except OSError:pass
 else:raise AssertionError(str(p))
for host in ['169.254.169.254','1.1.1.1']:
 try:socket.create_connection((host,80),timeout=.2)
 except OSError:pass
 else:raise AssertionError(host)
assert libc.unshare(0x10000000 | 0x00020000) == -1
(r/'candidate/denial-witness').write_text('all denied with process ASLR disabled')
print(json.dumps({{'personality':before,'uid':os.geteuid(),'seccomp':int(status['Seccomp']),'all_denied':True}}))
",
        crate::py::repr_str(&sp::text(work))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_programs_keep_their_former_argv() {
        let trusted = Path::new("/t");
        let names: Vec<&str> = regressions(trusted).iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            [
                "architecture-tooling-regressions",
                "toolchain-regressions",
                "conformance-capability-regressions",
                "conformance-confined-tools-regressions"
            ]
        );
        assert_eq!(regressions(trusted)[0].1[0], "/usr/bin/python3");
        assert_eq!(
            sigstore(Path::new("/r"), false).last().unwrap(),
            "--require"
        );
        assert!(denial_witness(Path::new("/w/it's")).contains("r=pathlib.Path(\"/w/it's\")"));
    }
}
