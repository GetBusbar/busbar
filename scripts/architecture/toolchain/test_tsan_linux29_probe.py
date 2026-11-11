"""The CI sanitizer delta has fixed bytes and never broadens other syscalls."""
import copy
import unittest

import tsan_linux29_probe as probe


class ProfileTests(unittest.TestCase):
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
