"""Controller-selected C TSan execution after same-runtime control qualification."""

from contextlib import contextmanager
from pathlib import Path
import shutil
import sys

from native_confinement import Execution, canonical, digest, require

# Only this trusted module's adjacent helper directory supplies the probe code.
sys.path.insert(0, str(Path(__file__).with_name("toolchain")))
from tsan_linux29_probe import PINS, ProfileExecution, derive, probe


class CUnitExecution(ProfileExecution):
    """A single fixed command; no profile selection is accepted from the child."""

    def __init__(self, original, baseline, profile, binary):
        require(type(original) is Execution, "sanitizer requires default confinement")
        super().__init__(original.config, original.roots, original.control, profile,
                         PINS["profile_sha256"], baseline)
        # Preserve dependency mounts, fixtures, and the receipt's observation list.
        # The already-validated default instance has no custom-profile fields.
        self.__dict__.update(original.__dict__)
        self.command = ["setarch", "--addr-no-randomize", str(binary)]

    @contextmanager
    def invocation(self, argv, cwd, env):
        require(list(map(str, argv)) == self.command,
                "sanitizer profile is restricted to the fixed C unit command")
        require(Path(cwd).resolve() == self.roots["checkout"],
                "sanitizer cwd differs from the qualified checkout")
        require(env.get("TSAN_OPTIONS") == "halt_on_error=1",
                "sanitizer error handling differs")
        with super().invocation(argv, cwd, env) as result:
            result[2]["sanitizer_profile_sha256"] = self.profile_sha256
            result[2]["sanitizer_scope"] = "c-unit-tsan"
            yield result


def run_c_unit_tsan(q):
    """Called only by the trusted C qualification branch, with no argv input."""
    original = getattr(q, "execution", None)
    require(type(original) is Execution, "C TSan requires confined execution")
    binary = q.work / "unit-tsan"
    require(binary.is_file() and not binary.is_symlink(),
            "C TSan requires a regular compiled unit binary")
    baseline = Path(__file__).with_name("toolchain") / "tsan-linux29-baseline.json"
    derive(baseline.read_bytes())
    config_path = q.control / "sanitizer-runtime-config.json"
    config_path.write_bytes(canonical(original.config))
    config_digest = digest(config_path)
    proof_work = q.control / "sanitizer-runtime-proof"
    try:
        proof = probe(config_path, config_digest, baseline, proof_work)
    finally:
        # Retain failed controls too, including failures before sample execution.
        for source, target in [("result.json", "sanitizer-runtime.json"),
                               ("engine.json", "sanitizer-engine.json")]:
            path = proof_work / source
            if path.is_file():
                shutil.copyfile(path, q.evidence / target)
    require(proof.get("status") == "native-x86-sanitizer-controls-pass"
            and proof.get("baseline_personality_denied") is True
            and proof.get("race_free_passed") is True
            and proof.get("deliberate_race_detected") is True
            and proof.get("denial_witness", {}).get("all_denied") is True
            and proof.get("image") == original.config["image"],
            "same-runtime sanitizer controls did not qualify")
    require(canonical(original.config) == config_path.read_bytes(),
            "runtime configuration changed after sanitizer controls")
    profile = proof_work / "profiles/sanitizer.json"
    sanitizer = CUnitExecution(original, baseline, profile, binary)
    q.receipt["sanitizer_runtime"] = {
        "configuration_sha256": config_digest,
        "controls_sha256": digest(q.evidence / "sanitizer-runtime.json"),
        "profile_sha256": PINS["profile_sha256"],
        "binary_sha256": digest(binary),
        "scope": "c-unit-tsan",
        "argv": sanitizer.command,
    }
    q.execution = sanitizer
    try:
        return q.run("c-unit-tsan", sanitizer.command)
    finally:
        q.execution = original
