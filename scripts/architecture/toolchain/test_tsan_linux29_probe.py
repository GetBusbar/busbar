"""The CI sanitizer delta has fixed bytes and never broadens other syscalls."""
import copy
import errno
import json
import subprocess
import unittest
from unittest.mock import MagicMock

import tsan_linux29_probe as probe


class ProfileTests(unittest.TestCase):
    def test_exact_successful_personality_denial_is_required(self):
        observation = {"argument": 262144, "before": 0, "result": -1,
                       "errno": errno.EPERM, "after": 0}
        probe.verify_baseline_personality(
            subprocess.CompletedProcess([], 0, json.dumps(observation), ""))
        for key, value in [("result", 0), ("errno", errno.EINVAL),
                           ("argument", 262145), ("after", 262144)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.verify_baseline_personality(subprocess.CompletedProcess(
                    [], 0, json.dumps({**observation, key: value}), ""))

    def test_baseline_startup_crash_or_diagnostic_cannot_substitute_for_denial(self):
        for code, stderr in [(245, ""), (66, "FATAL: unexpected memory mapping"),
                             (1, "personality: Operation not permitted")]:
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, "exit successfully"):
                probe.verify_baseline_personality(
                    subprocess.CompletedProcess([], code, "", stderr))
        with self.assertRaises(json.JSONDecodeError):
            probe.verify_baseline_personality(subprocess.CompletedProcess([], 0, "", ""))

    def test_exact_verified_ubuntu_build_is_required(self):
        observed = {"Version": "29.1.3", "GitCommit": "29.1.3-0ubuntu3~24.04.2"}
        probe.verify_engine(observed)
        for key, value in [
            ("Version", "29.1.4"),
            ("GitCommit", "29.1.3-0ubuntu3~24.04.1"),
            ("GitCommit", "fbf3ed2"),
            ("GitCommit", ""),
            ("GitCommit", "29.1.3-0ubuntu3~24.04.2-modified"),
        ]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                probe.verify_engine({**observed, key: value})

    def test_engine_response_is_retained_before_identity_rejection(self):
        actual = {"Version": "29.1.3", "GitCommit": "unexpected-build"}
        execution, work = MagicMock(), MagicMock()
        execution._client.return_value = subprocess.CompletedProcess(
            [], 0, json.dumps(actual), ""
        )
        observed = probe.observe_engine(execution, work)
        with self.assertRaisesRegex(ValueError, "unexpected-build"):
            probe.verify_engine(observed)
        work.__truediv__.assert_called_once_with("engine.json")
        retained = json.loads(work.__truediv__.return_value.write_text.call_args.args[0])
        self.assertEqual(json.loads(retained["stdout"]), actual)

    def test_invalid_engine_response_is_also_retained(self):
        execution, work = MagicMock(), MagicMock()
        execution._client.return_value = subprocess.CompletedProcess([], 0, "invalid", "")
        with self.assertRaises(json.JSONDecodeError):
            probe.observe_engine(execution, work)
        work.__truediv__.return_value.write_text.assert_called_once()

    def test_engine_pin_is_distinct_from_local_arm_policy(self):
        self.assertEqual(probe.PINS["engine_version"], "29.1.3")
        self.assertEqual(probe.PINS["allowed_personality"], 262144)
        self.assertEqual(probe.PINS["profile_sha256"],
                         "8901a497db4e8270de320dfd06b5af316ab7c6bea6fdc24f2c91e362c83295f3")

    def test_unknown_baseline_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "baseline differs"):
            probe.derive(b'{}')

    def test_delta_rejects_wildcards_and_additional_authority(self):
        baseline = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
        for change in ("wildcard", "extra_flag", "extra_syscall", "default"):
            result = copy.deepcopy(baseline)
            result["syscalls"].append(copy.deepcopy(probe.RULE))
            if change == "wildcard":
                result["syscalls"][0].pop("args")
            elif change == "extra_flag":
                result["syscalls"][0]["args"][0]["value"] |= 0x0400000
            elif change == "extra_syscall":
                result["syscalls"][0]["names"].append("ptrace")
            else:
                result["defaultAction"] = "SCMP_ACT_ALLOW"
            with self.subTest(change=change), self.assertRaises(ValueError):
                probe.verify_delta(baseline, result)


if __name__ == "__main__":
    unittest.main()
