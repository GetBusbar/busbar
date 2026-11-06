#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Targeted sensitivity checks for the listener-isolation audit observation."""
import base64
import json
import copy
import importlib.util
import pathlib
import os
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("evidence", pathlib.Path(__file__).parents[1] / "evidence.py")
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class IsolationAuditTests(unittest.TestCase):
    def setUp(self):
        observer = dict(op_class="admin_read", outcome="Completed", step="", finish="Complete",
                        subject_tag="principal", subject_value="observer", destination="",
                        lines_count="0", lines=[], fee_count="0", children_count="0", children=[],
                        emission_delta="0", hold_ref="", settle_ref="", slice_ref="", lease_ref="")
        self.control = [observer]
        self.attempt = [dict(observer, subject_value="another-observer")]
        for index in range(8):
            record = copy.deepcopy(observer)
            record.update(op_class="", finish="Error", subject_value="anonymous" if index < 6 else "vk_test",
                          outcome="Refused(Authenticate, Unauthenticated)" if index < 6 else "Refused(Decode, DecodeFailed)",
                          step="authenticate" if index < 6 else "decode")
            self.attempt.append(record)

    def judge(self, attempt):
        return evidence.isolation_audit_findings(self.control, attempt, "vk_test", "observer", "another-observer")

    def test_all_eight_refusals_are_required_and_admitted(self):
        self.assertEqual(self.judge(self.attempt), [])
        for index in range(9):
            with self.subTest(missing=index):
                self.assertTrue(self.judge(self.attempt[:index] + self.attempt[index + 1:]))
        self.assertTrue(self.judge(self.attempt + [self.attempt[-1]]))

    def test_completed_or_late_refused_work_is_never_ignored(self):
        for outcome, step in (("Completed", ""), ("Refused(Admit, Denied)", "admit"),
                              ("Refused(Route, NotFound)", "route")):
            for index in range(1, 9):
                with self.subTest(outcome=outcome, index=index):
                    attempt = copy.deepcopy(self.attempt)
                    attempt[index].update(outcome=outcome, step=step)
                    self.assertTrue(self.judge(attempt))

    def test_refusal_cannot_hide_effects_or_wrong_identity(self):
        mutations = dict(op_class="admin_write", destination="upstream", fee_count="1",
                         lines_count="1", lines=[{"class": "request", "quantity": "1"}],
                         children_count="1", children=["123"], emission_delta="1",
                         hold_ref="hold", settle_ref="settled", slice_ref="slice", lease_ref="lease",
                         subject_value="another-principal", subject_tag="anonymous", finish="Complete")
        for field, value in mutations.items():
            for index in range(1, 9):
                with self.subTest(field=field, index=index):
                    attempt = copy.deepcopy(self.attempt)
                    attempt[index][field] = value
                    self.assertTrue(self.judge(attempt))

    def test_wrong_refusal_stage_and_reordered_probes_fail(self):
        attempt = copy.deepcopy(self.attempt)
        attempt[1], attempt[8] = attempt[8], attempt[1]
        self.assertTrue(self.judge(attempt))
        attempt = copy.deepcopy(self.attempt)
        attempt[7]["step"] = "authenticate"
        self.assertTrue(self.judge(attempt))

    def test_observer_cannot_hide_mutation_or_billing(self):
        for field, value in (("op_class", "admin_write"), ("fee_count", "1"),
                             ("outcome", "Refused(Authenticate, Unauthenticated)")):
            with self.subTest(field=field):
                control = copy.deepcopy(self.control)
                control[0][field] = value
                self.assertTrue(evidence.isolation_audit_findings(control, self.attempt, "vk_test", "observer", "another-observer"))
                attempt = copy.deepcopy(self.attempt)
                attempt[0][field] = value
                self.assertTrue(self.judge(attempt))

    def test_judge_correlates_each_fresh_observer_credential(self):
        heads = iter((1, 2, 4, 13))
        minted = []
        head_principals = []

        def full():
            claims = {"iss": evidence.ISS, "sub": f"subject-{len(minted)}"}
            payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
            headers = {"authorization": f"Bearer header.{payload}.signature"}
            minted.append(headers)
            return headers

        def request(port, method, path, *, headers, body=None):
            if port == 2:
                if path.endswith("/audit/head"):
                    payload = headers["authorization"].split(".")[1]
                    subject = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["sub"]
                    head_principals.append(f"oidc-v2:{evidence.oidf.b64url(evidence.ISS.encode())}:{subject}")
                    return 200, {"head": {"seq": next(heads)}}
                if "/audit/range?" in path:
                    control = "from=2&" in path
                    records, start = ((self.control, 2) if control else (self.attempt, 5))
                    records = [dict(record, seq=str(start + n)) for n, record in enumerate(records)]
                    records[0]["subject_value"] = head_principals[0 if control else 2]
                    return 200, {"records": records}
                return 200, {"items": [{"id": "vk_test"}], "next_cursor": None}
            return (404 if headers.get("authorization") == "Bearer live-token" else 401), {"error": {}}

        with tempfile.TemporaryDirectory() as output, mock.patch.dict(os.environ, CONFORMANCE_OUT=output), \
                mock.patch.object(evidence, "request", request):
            self.assertEqual(evidence.judge_data_admin_isolation(1, 2, full, "live-token", "vk_test"), [])
        self.assertEqual(len(head_principals), 4)
        self.assertEqual(len(set(head_principals)), 4)
        self.assertEqual(len(minted), 10)

    def test_observer_identity_substitution_or_missing_identity_fails(self):
        for value in (None, "", False, "substituted-observer"):
            with self.subTest(value=value):
                attempt = copy.deepcopy(self.attempt)
                attempt[0]["subject_value"] = value
                self.assertTrue(self.judge(attempt))
        for value in (None, "", False):
            with self.subTest(control_value=value):
                control = copy.deepcopy(self.control)
                control[0]["subject_value"] = value
                self.assertTrue(evidence.isolation_audit_findings(control, self.attempt, "vk_test", "observer", "another-observer"))
        attempt = copy.deepcopy(self.attempt)
        del attempt[0]["subject_value"]
        self.assertTrue(self.judge(attempt))

    def test_missing_or_noncanonical_effect_fields_fail_closed(self):
        for field in ("lines_count", "fee_count", "children_count", "emission_delta", "destination"):
            with self.subTest(field=field):
                attempt = copy.deepcopy(self.attempt)
                del attempt[1][field]
                self.assertTrue(self.judge(attempt))
        attempt = copy.deepcopy(self.attempt)
        attempt[1]["fee_count"] = False
        self.assertTrue(self.judge(attempt))


if __name__ == "__main__":
    unittest.main()
