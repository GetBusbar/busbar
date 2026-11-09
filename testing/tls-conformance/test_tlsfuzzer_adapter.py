# SPDX-License-Identifier: Apache-2.0
"""Targeted fail-closed adapter checks; never opens a TLS connection."""
import collections
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("adapter", Path(__file__).with_name("tlsfuzzer.py"))
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)

ALGORITHMS = ["rsa_pkcs1_sha512", "rsa_pkcs1_sha384", "rsa_pkcs1_sha256", "rsa_pkcs1_sha224",
              "rsa_pkcs1_sha1", "(1, 1)", "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384",
              "rsa_pss_rsae_sha512", "rsa_pss_pss_sha256", "rsa_pss_pss_sha384", "rsa_pss_pss_sha512"]


def transcript(roster, negative=False, **counts):
    actual = dict(TOTAL=len(roster), SKIP=0, PASS=0 if negative else len(roster),
                  XFAIL=0, FAIL=len(roster) if negative else 0, XPASS=0)
    actual.update(counts)
    return ("\n".join(name + " ..." for name in roster) + "\nversion: 9\n" +
            "\n".join(f"{name}: {value}" for name, value in actual.items()) + "\n")


class AdapterChecks(unittest.TestCase):
    def test_entire_applicable_rsa_2048_roster_is_2068_executions(self):
        roster = adapter.expected_cases(256, ALGORITHMS)
        self.assertEqual(len(roster), 2068)
        self.assertEqual(collections.Counter(roster)["sanity"], 2)
        self.assertEqual(sum("Malformed rsa - xor" in name for name in roster), 2048)
        self.assertFalse(set(roster) & set(adapter.EXCLUDED))
        self.assertEqual(adapter.judge(transcript(roster), 0, roster)["PASS"], 2068)

    def test_skipped_failed_xfailed_or_missing_cases_cannot_pass(self):
        roster = adapter.expected_cases(256, ALGORITHMS)
        for counts in ({"SKIP": 1}, {"FAIL": 1}, {"XFAIL": 1}, {"XPASS": 1}, {"TOTAL": 0}):
            with self.subTest(counts=counts), self.assertRaises(adapter.Refused):
                adapter.judge(transcript(roster, **counts), 0, roster)
        with self.assertRaises(adapter.Refused):
            adapter.judge(transcript(roster[:-1]), 0, roster)

    def test_duplicate_or_missing_summary_and_nonzero_exit_are_refused(self):
        text = transcript(["sanity"])
        for bad, rc in ((text + "TOTAL: 1\n", 0), (text.replace("version: 9", "version: 10"), 0),
                        ("", 0), (text, 1)):
            with self.subTest(text=bad[:20], rc=rc), self.assertRaises(adapter.Refused):
                adapter.judge(bad, rc, ["sanity"])

    def test_wrong_ca_control_requires_actual_upstream_trust_alert(self):
        text = transcript(["sanity"], negative=True)
        with self.assertRaises(adapter.Refused):
            adapter.judge(text, 1, ["sanity"], negative=True)
        self.assertEqual(adapter.judge(text + "Alert(fatal, unknown_ca)", 1,
                                      ["sanity"], negative=True)["FAIL"], 1)

    def test_zero_or_weak_key_profile_is_refused(self):
        for octets, algorithms in ((0, ALGORITHMS), (128, ALGORITHMS), (256, [])):
            with self.assertRaises(adapter.Refused):
                adapter.expected_cases(octets, algorithms)

    def test_source_workspace_cannot_be_published_as_evidence(self):
        with self.assertRaises(adapter.Refused):
            adapter.Profile("/fixture", "/fixture", "/checkout", "/binary")

    def test_changed_upstream_script_is_refused(self):
        profile = adapter.Profile.__new__(adapter.Profile)
        profile.source = Path("/pinned-source")
        with mock.patch.object(adapter, "capture", side_effect=[adapter.REVISION, ""]), \
                mock.patch.object(adapter, "digest", return_value="tampered"):
            with self.assertRaises(adapter.Refused):
                profile.check_source()

    def test_missing_or_failed_required_leg_cannot_finish_green(self):
        profile = adapter.Profile.__new__(adapter.Profile)
        profile.record = {"legs": {"control": {"pass": True}}}
        profile.save = mock.Mock()
        self.assertTrue(profile.finish())
        self.assertFalse(profile.record["pass"])

    def test_timeout_terminates_owned_process_group_and_is_not_a_verdict(self):
        process = mock.Mock(pid=123)
        process.wait.side_effect = [subprocess.TimeoutExpired(["upstream"], 1), 0]
        with mock.patch.object(Path, "open", return_value=io.BytesIO()), \
                mock.patch.object(adapter.subprocess, "Popen", return_value=process), \
                mock.patch.object(adapter.os, "killpg") as kill:
            with self.assertRaises(adapter.Refused):
                adapter.bounded(["upstream"], "upstream.log", 1)
        self.assertEqual(kill.call_args_list, [mock.call(123, adapter.signal.SIGTERM),
                                              mock.call(123, adapter.signal.SIGKILL)])


if __name__ == "__main__":
    unittest.main()
