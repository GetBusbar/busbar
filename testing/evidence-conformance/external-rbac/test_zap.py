from collections import Counter
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import zap
from test_report import html


class Credentials(unittest.TestCase):
    def setUp(self):
        self.c = zap.Credentials.__new__(zap.Credentials)
        self.c.requests = Counter()
        self.c.responses = Counter()
        self.c.statuses = {}
        self.c.errors = []
        self.mints = 0

        def mint():
            self.mints += 1
            return {"authorization": "Bearer fixture-" + str(self.mints)}

        self.c.begin(
            "POST", "http://127.0.0.1:1234/admin/keys", {"operator": (mint, None)}
        )
        self.args = {
            "method": "POST",
            "uri": "http://127.0.0.1:1234/admin/keys",
            "user": "operator",
        }

    def test_one_fresh_credential_and_response_per_cell(self):
        self.assertEqual(
            self.c.exchange({**self.args, "phase": "request"}),
            {"authorization": "Bearer fixture-1"},
        )
        self.c.exchange({**self.args, "phase": "response", "status": "403"})
        receipt = self.c.finish()
        self.assertEqual(receipt, {"operator": 403})
        self.assertEqual(self.mints, 1)
        self.assertNotIn("Bearer", json.dumps(receipt))

    def test_wrong_principal_method_uri_or_phase_refused(self):
        for patch in (
            {"user": "attacker"},
            {"method": "GET"},
            {"uri": "http://example.com/"},
            {"phase": "unexpected"},
        ):
            with self.subTest(patch=patch), self.assertRaises(zap.Refused):
                self.c.exchange({**self.args, "phase": "request", **patch})
        self.assertEqual(self.mints, 0)

    def test_duplicate_request_or_missing_response_cannot_pass(self):
        self.c.exchange({**self.args, "phase": "request"})
        with self.assertRaises(zap.Refused):
            self.c.exchange({**self.args, "phase": "request"})
        with self.assertRaises(zap.Refused):
            self.c.finish()

    def test_absent_credentials_do_not_inherit_prior_headers(self):
        self.c.begin("GET", self.args["uri"], {"none": (lambda: {}, None)})
        self.assertEqual(
            self.c.exchange(
                {**self.args, "user": "none", "method": "GET", "phase": "request"}
            ),
            {"authorization": None},
        )


class Inputs(unittest.TestCase):
    def test_nonloopback_destination_refused(self):
        for uri in (
            "http://example.com/a",
            "https://127.0.0.1/a",
            "http://127.0.0.2/a",
        ):
            with self.subTest(uri=uri), self.assertRaises(zap.Refused):
                zap.raw_request("GET", uri, "")

    def test_raw_seed_contains_method_body_and_no_credentials(self):
        raw = zap.raw_request("POST", "http://127.0.0.1:1234/admin/keys", "{}")
        self.assertTrue(
            raw.startswith("POST http://127.0.0.1:1234/admin/keys HTTP/1.1\r\n")
        )
        self.assertTrue(raw.endswith("Content-Length: 2\r\n\r\n{}"))
        self.assertNotIn("Authorization:", raw)
        self.assertNotIn("Cookie:", raw)

    def test_bad_download_digest_fails_before_use(self):
        with tempfile.TemporaryDirectory() as work:
            destination = Path(work) / "archive"
            import io

            with mock.patch.object(
                zap.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong archive")
            ):
                with self.assertRaises(zap.Refused):
                    zap.download(
                        {"url": "https://example.invalid", "sha256": "0" * 64},
                        destination,
                    )

    def test_private_credentials_cannot_enter_published_output(self):
        with tempfile.TemporaryDirectory() as work:
            with self.assertRaises(zap.Refused):
                zap.ExternalRBAC(work, work)

    def test_lock_covers_all_required_addons_and_jre_platforms(self):
        self.assertEqual(len(zap.LOCK["bundled_plugins"]), 4)
        self.assertEqual(
            {a["name"] for a in zap.LOCK["addons"]},
            {"accessControl-alpha-13.zap", "commonlib-release-1.40.0.zap"},
        )
        self.assertEqual(
            set(zap.LOCK["jre"]["platforms"]),
            {"Darwin-arm64", "Darwin-x86_64", "Linux-aarch64", "Linux-x86_64"},
        )
        items = [
            zap.LOCK["runtime"],
            *zap.LOCK["addons"],
            *zap.LOCK["jre"]["platforms"].values(),
        ]
        for item in items:
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(item["url"].startswith("https://github.com/"))


class Matrix(unittest.TestCase):
    def test_operation_sessions_and_all_users_are_required(self):
        with tempfile.TemporaryDirectory() as work:
            runner = zap.ExternalRBAC(work, Path(work) / "reports")
            runner.credentials = zap.Credentials.__new__(zap.Credentials)
            runner.credentials.url = "http://127.0.0.1:1/test"
            runner.credentials.requests = Counter()
            runner.credentials.responses = Counter()
            runner.credentials.statuses = {}
            runner.credentials.errors = []
            names = ["reader"]
            calls = []
            state = {}

            def api(component, kind, action, **params):
                calls.append((component, action, params))
                if action == "newContext":
                    state["name"] = params["contextName"]
                    return {"contextId": "1"}
                if action == "newUser":
                    return {"userId": "1"}
                if action == "setGlobalVar" and params["varKey"] == "busbar.operation":
                    state["operation"] = json.loads(params["varValue"])
                if action == "globalVar":
                    if params["varKey"] == "busbar.rules.ready":
                        op = state["operation"]
                        return {
                            "globalVar": json.dumps(
                                {"method": op["method"], "uri": op["uri"], "cells": 1}
                            )
                        }
                    return {"globalVar": ""}
                if action == "getScanProgress":
                    c = runner.credentials
                    for name in names:
                        c.requests[name] = c.responses[name] = 1
                        c.statuses[name] = 200
                    return {"getScanProgress": "100"}
                if action == "writeHTMLreport":
                    op = state["operation"]
                    Path(params["fileName"]).write_text(
                        html(method=op["method"]).replace(
                            "http://localhost/admin/keys", op["uri"]
                        )
                    )
                return {"Result": "OK"}

            runner.api = api
            receipt = runner.matrix(
                "control-full",
                1234,
                [
                    ("GET", "/admin/keys", "read-only", "get_keys"),
                    ("POST", "/admin/keys", "full", "post_keys"),
                ],
                {"reader": (lambda: {}, lambda s, v: "admit")},
                concrete=lambda p: p,
            )
            for artifact in (runner.output / "control-full").glob("*.json"):
                json.loads(artifact.read_text())
            self.assertTrue(receipt["passed"])
            self.assertEqual(receipt["actual_cells"], 2)
            self.assertEqual(sum(a == "newSession" for _, a, _ in calls), 2)
            self.assertEqual(sum(a == "scan" for _, a, _ in calls), 2)
            self.assertEqual(
                len(list((runner.output / "control-full").glob("*.html"))), 2
            )
            with self.assertRaises(zap.Refused):
                runner.complete()  # Two green cells cannot stand for the mandatory ten legs.

    def test_negative_requires_scope_and_expiry_not_unrelated_failure(self):
        principals = {
            "reader": (lambda: {}, lambda s, v: "forbid"),
            "expired": (lambda: {}, lambda s, v: "deny"),
            "full": (lambda: {}, lambda s, v: "admit"),
        }
        cases = [
            ({"reader": "ILLEGAL", "expired": "ILLEGAL", "full": "VALID"}, True),
            ({"reader": "VALID", "expired": "ILLEGAL", "full": "VALID"}, False),
            ({"reader": "ILLEGAL", "expired": "VALID", "full": "VALID"}, False),
            ({"reader": "ILLEGAL", "expired": "ILLEGAL", "full": "ILLEGAL"}, False),
            ({"reader": "UNKNOWN", "expired": "ILLEGAL", "full": "VALID"}, False),
        ]
        for verdicts, should_pass in cases:
            with self.subTest(verdicts=verdicts), tempfile.TemporaryDirectory() as work:
                runner = zap.ExternalRBAC(work, Path(work) / "reports")
                c = zap.Credentials.__new__(zap.Credentials)
                c.url, c.requests, c.responses, c.statuses, c.errors = (
                    "unused",
                    Counter(),
                    Counter(),
                    {},
                    [],
                )
                runner.credentials = c
                state = {}

                def api(component, kind, action, **params):
                    if action == "newContext":
                        return {"contextId": "1"}
                    if action == "newUser":
                        return {
                            "userId": str(list(principals).index(params["name"]) + 1)
                        }
                    if (
                        action == "setGlobalVar"
                        and params["varKey"] == "busbar.operation"
                    ):
                        state.update(json.loads(params["varValue"]))
                    if action == "globalVar":
                        if params["varKey"] == "busbar.rules.ready":
                            return {
                                "globalVar": json.dumps(
                                    {
                                        "method": state["method"],
                                        "uri": state["uri"],
                                        "cells": 3,
                                    }
                                )
                            }
                        return {"globalVar": ""}
                    if action == "getScanProgress":
                        for name in principals:
                            c.requests[name] = c.responses[name] = 1
                            c.statuses[name] = 200
                        return {"getScanProgress": "100"}
                    if action == "writeHTMLreport":
                        head = "".join(
                            '<th colspan="2">' + name + "</th>" for name in principals
                        )
                        cols = "".join(
                            "<th>Authorization</th><th>Access control</th>"
                            for name in principals
                        )
                        cells = "".join(
                            '<td>Authorized</td><td class="'
                            + verdicts[name]
                            + '">label</td>'
                            for name in principals
                        )
                        table = (
                            '<table id="table"><tr><th></th><th></th>'
                            + head
                            + "</tr><tr><th>Method</th><th>URL</th>"
                            + cols
                            + "</tr>"
                        )
                        table += (
                            "<tr><td>POST</td><td>"
                            + state["uri"]
                            + "</td>"
                            + cells
                            + "</tr></table>"
                        )
                        Path(params["fileName"]).write_text(table)
                    return {"Result": "OK"}

                runner.api = api

                def run():
                    return runner.matrix(
                        "negative-full",
                        1234,
                        [("POST", "/admin/keys", "full", "post_keys")],
                        principals,
                        concrete=lambda p: p,
                        negative=True,
                    )

                if should_pass:
                    self.assertTrue(run()["passed"])
                else:
                    with self.assertRaises(zap.Refused):
                        run()

    def test_unknown_or_missing_report_cell_fails_matrix(self):
        # The exact accounting implementation is exercised with realistic upstream HTML
        # in test_report; the orchestration consumes that parser directly.
        with self.assertRaises(zap.Refused):
            zap.report.read_cells(
                html(verdict="UNKNOWN").replace("<td>Authorized</td>", ""),
                "GET",
                "http://localhost/admin/keys",
                ["reader"],
            )


if __name__ == "__main__":
    unittest.main()
