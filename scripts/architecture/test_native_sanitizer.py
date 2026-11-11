"""Only a freshly qualified runtime can execute the fixed C TSan command."""

import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from native_confinement import Execution
import native_sanitizer as sanitizer


class SanitizerActivation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        control, work, evidence = root / "control", root / "candidate", root / "evidence"
        for path in (control, work, evidence):
            path.mkdir()
        (work / "unit-tsan").write_bytes(b"instrumented binary fixture")
        original = object.__new__(Execution)
        original.config = {"image": "fixture@sha256:" + "1" * 64}
        original.observations = []
        self.q = SimpleNamespace(execution=original, control=control, work=work,
                                 evidence=evidence, receipt={}, run=Mock())
        self.original = original

    def proof(self, config, expected, baseline, output):
        self.assertEqual(json.loads(config.read_text()), self.original.config)
        self.assertEqual(sanitizer.digest(config), expected)
        sanitizer.derive(baseline.read_bytes())
        output.mkdir()
        report = {"status": "native-x86-sanitizer-controls-pass",
                  "baseline_personality_denied": True,
                  "race_free_passed": True, "deliberate_race_detected": True,
                  "denial_witness": {"all_denied": True},
                  "image": self.original.config["image"]}
        (output / "result.json").write_text(json.dumps(report))
        (output / "engine.json").write_text("{}")
        return report

    def test_only_successful_controls_select_profile_and_restore_default(self):
        selected = SimpleNamespace(command=["setarch", "--addr-no-randomize",
                                            str(self.q.work / "unit-tsan")])
        self.q.run.side_effect = lambda *_: self.assertIs(self.q.execution, selected)
        with patch.object(sanitizer, "probe", side_effect=self.proof), \
                patch.object(sanitizer, "CUnitExecution", return_value=selected) as factory:
            sanitizer.run_c_unit_tsan(self.q)
        factory.assert_called_once()
        self.q.run.assert_called_once_with("c-unit-tsan", selected.command)
        self.assertIs(self.q.execution, self.original)
        self.assertEqual(self.q.receipt["sanitizer_runtime"]["scope"], "c-unit-tsan")

    def test_product_failure_restores_default_and_is_not_suppressed(self):
        selected = SimpleNamespace(command=["setarch", "--addr-no-randomize",
                                            str(self.q.work / "unit-tsan")])
        self.q.run.side_effect = subprocess.CalledProcessError(66, selected.command)
        with patch.object(sanitizer, "probe", side_effect=self.proof), \
                patch.object(sanitizer, "CUnitExecution", return_value=selected), \
                self.assertRaises(subprocess.CalledProcessError):
            sanitizer.run_c_unit_tsan(self.q)
        self.assertIs(self.q.execution, self.original)

    def test_failed_controls_preserve_evidence_and_never_select_profile(self):
        def fail(*args):
            self.proof(*args)
            raise ValueError("race control failed")
        with patch.object(sanitizer, "probe", side_effect=fail), \
                patch.object(sanitizer, "CUnitExecution") as factory, \
                self.assertRaisesRegex(ValueError, "race control failed"):
            sanitizer.run_c_unit_tsan(self.q)
        factory.assert_not_called()
        self.q.run.assert_not_called()
        self.assertIs(self.q.execution, self.original)
        self.assertTrue((self.q.evidence / "sanitizer-runtime.json").is_file())

    def test_unqualified_returned_controls_fail_closed(self):
        for field, value in [("baseline_personality_denied", False),
                             ("race_free_passed", False),
                             ("deliberate_race_detected", False),
                             ("denial_witness", {"all_denied": False}),
                             ("image", "different")]:
            def incomplete(*args):
                result = self.proof(*args)
                result[field] = value
                return result
            with self.subTest(field=field), \
                    patch.object(sanitizer, "probe", side_effect=incomplete), \
                    patch.object(sanitizer, "CUnitExecution") as factory, \
                    self.assertRaisesRegex(ValueError, "did not qualify"):
                sanitizer.run_c_unit_tsan(self.q)
            factory.assert_not_called()
            self.q.run.assert_not_called()
            shutil.rmtree(self.q.control / "sanitizer-runtime-proof")

    def test_execution_keeps_original_observations_and_mount_state(self):
        self.original.roots = {"checkout": Path("/checkout")}
        self.original.control = Path("/control")
        self.original.dependency_seed = Path("/dependency-seed")

        def initialize(instance, *_args):
            instance.profile = Path("/controller/sanitizer.json")
            instance.profile_sha256 = sanitizer.PINS["profile_sha256"]

        with patch.object(sanitizer.ProfileExecution, "__init__", initialize):
            selected = sanitizer.CUnitExecution(self.original, Path("/baseline"),
                                               Path("/profile"), self.q.work / "unit-tsan")
        self.assertIs(selected.observations, self.original.observations)
        self.assertIs(selected.config, self.original.config)
        self.assertEqual(selected.dependency_seed, self.original.dependency_seed)
        self.assertEqual(selected.profile, Path("/controller/sanitizer.json"))

    def test_changed_runtime_configuration_is_rejected_after_controls(self):
        def changed(*args):
            result = self.proof(*args)
            self.original.config["docker_host"] = "unix:///other.sock"
            return result
        with patch.object(sanitizer, "probe", side_effect=changed), \
                patch.object(sanitizer, "CUnitExecution") as factory, \
                self.assertRaisesRegex(ValueError, "configuration changed"):
            sanitizer.run_c_unit_tsan(self.q)
        factory.assert_not_called()
        self.q.run.assert_not_called()

    def test_confined_execution_is_mandatory(self):
        self.q.execution = None
        with self.assertRaisesRegex(ValueError, "requires confined execution"):
            sanitizer.run_c_unit_tsan(self.q)
        self.q.run.assert_not_called()

    def test_execution_scope_rejects_other_commands_cwd_or_flags(self):
        execution = object.__new__(sanitizer.CUnitExecution)
        execution.command = ["setarch", "--addr-no-randomize", "/candidate/unit-tsan"]
        execution.roots = {"checkout": Path("/checkout")}
        for command, cwd, env in [
            (["sh"], "/checkout", {"TSAN_OPTIONS": "halt_on_error=1"}),
            (execution.command, "/other", {"TSAN_OPTIONS": "halt_on_error=1"}),
            (execution.command, "/checkout", {"TSAN_OPTIONS": "halt_on_error=0"}),
        ]:
            with self.subTest(command=command, cwd=cwd, env=env), \
                    patch.object(sanitizer.ProfileExecution, "invocation") as parent, \
                    self.assertRaises(ValueError):
                with execution.invocation(command, cwd, env):
                    self.fail("scope escaped")
            parent.assert_not_called()


if __name__ == "__main__":
    unittest.main()
