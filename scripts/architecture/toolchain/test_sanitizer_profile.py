"""The dedicated profile cannot broaden any rule beyond one exact argument."""

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

import sanitizer_profile as policy


class Profile(unittest.TestCase):
    def setUp(self):
        self.baseline = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 1,
            "archMap": [{"architecture": "SCMP_ARCH_AARCH64"}],
            "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}],
        }
        self.raw = policy.canonical(self.baseline)

    def derive(self):
        with patch.dict(
            policy.PINS, baseline_sha256=hashlib.sha256(self.raw).hexdigest()
        ):
            return policy.derive(self.raw)

    def test_exact_argument_is_the_only_delta(self):
        actual = self.derive()
        self.assertEqual(actual["syscalls"], [*self.baseline["syscalls"], policy.RULE])
        self.assertEqual(
            actual["syscalls"][-1]["args"],
            [{"index": 0, "value": 262144, "op": "SCMP_CMP_EQ"}],
        )
        policy.verify_delta(self.baseline, actual)

    def test_wrong_baseline_and_repeated_exception_refuse(self):
        with self.assertRaisesRegex(ValueError, "baseline differs"):
            policy.derive(self.raw)
        changed = copy.deepcopy(self.baseline)
        changed["syscalls"].append(copy.deepcopy(policy.RULE))
        raw = policy.canonical(changed)
        with patch.dict(policy.PINS, baseline_sha256=hashlib.sha256(raw).hexdigest()):
            with self.assertRaisesRegex(ValueError, "unexpected baseline"):
                policy.derive(raw)

    def test_wildcard_mask_other_flags_syscalls_and_defaults_refuse(self):
        valid = self.derive()
        changes = [
            lambda p: p["syscalls"][-1].update(args=[]),
            lambda p: p["syscalls"][-1]["args"][0].update(op="SCMP_CMP_MASKED_EQ"),
            lambda p: p["syscalls"][-1]["args"][0].update(value=262144 | 0x0400000),
            lambda p: p["syscalls"][-1]["names"].append("ptrace"),
            lambda p: p["syscalls"].append(
                {"names": ["mount"], "action": "SCMP_ACT_ALLOW"}
            ),
            lambda p: p.update(defaultAction="SCMP_ACT_ALLOW"),
            lambda p: p.update(archMap=[]),
            lambda p: p["syscalls"][0]["names"].append("unshare"),
        ]
        for change in changes:
            actual = copy.deepcopy(valid)
            change(actual)
            with self.subTest(profile=json.dumps(actual)):
                with self.assertRaises(ValueError):
                    policy.verify_delta(self.baseline, actual)


if __name__ == "__main__":
    unittest.main()
