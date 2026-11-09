"""Fail-closed accounting of unmodified ZAP AccessControl v13 HTML results.

This reads the upstream judge's VALID/ILLEGAL/UNKNOWN classifications; it does
not classify HTTP responses. It is not a scanner or a certification verdict.
Use one operation per report: v13's reporter collapses methods sharing a URI.
"""
from html.parser import HTMLParser


class Refused(ValueError):
    pass


class Report(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables = 0
        self.depth = 0
        self.rows = []
        self.row = None
        self.cell = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "table":
            if self.depth:
                raise Refused("nested report table")
            if attrs.get("id") == "table":
                self.tables += 1
                self.depth = 1
        if not self.depth:
            return
        if tag == "tr":
            if self.row is not None:
                raise Refused("nested report row")
            self.row = []
        elif tag in ("td", "th"):
            if self.row is None or self.cell is not None:
                raise Refused("malformed report cell")
            self.cell = {"text": "", "class": attrs.get("class"),
                         "colspan": attrs.get("colspan"), "tag": tag}

    def handle_data(self, data):
        if self.cell is not None:
            self.cell["text"] += data

    def handle_endtag(self, tag):
        if not self.depth:
            return
        if tag in ("td", "th"):
            if self.cell is None:
                raise Refused("unbalanced report cell")
            self.cell["text"] = self.cell["text"].strip()
            self.row.append(self.cell)
            self.cell = None
        elif tag == "tr":
            if self.row is None or self.cell is not None:
                raise Refused("unbalanced report row")
            self.rows.append(self.row)
            self.row = None
        elif tag == "table":
            if self.row is not None:
                raise Refused("unterminated report row")
            self.depth = 0


def assess(html, method, uri, principals):
    """Require exactly the declared operation×principal roster, all upstream VALID.

    `principals` is the ordered roster exported by the prepared ZAP context,
    including its actual upstream unauthenticated-user label when applicable.
    ALLOWED/DENIED rules and authorization detection must be configured before
    scanning; report validity alone cannot prove those inputs were correct.
    """
    if not principals or len(principals) != len(set(principals)):
        raise Refused("empty or duplicate principal roster")
    parser = Report()
    parser.feed(html)
    parser.close()
    if parser.tables != 1 or parser.depth or parser.cell is not None:
        raise Refused("missing, duplicate or incomplete upstream table")
    if len(parser.rows) != 3:
        raise Refused("expected exactly one operation, not a combined-method report")
    users, headers, row = parser.rows
    if len(users) != 2 + len(principals) or any(c["text"] for c in users[:2]):
        raise Refused("unexpected principal header")
    if [c["text"] for c in users[2:]] != list(principals):
        raise Refused("upstream principal roster mismatch")
    if any(c["colspan"] != "2" or c["tag"] != "th" for c in users[2:]):
        raise Refused("unexpected upstream principal header layout")
    width = 2 + 2 * len(principals)
    if len(headers) != width or len(row) != width:
        raise Refused("missing or extra upstream cells")
    if row[0]["text"] != method or row[1]["text"] != uri:
        raise Refused("upstream operation mismatch (possibly collapsed HTTP methods)")
    results = []
    for i, principal in enumerate(principals):
        authorization, verdict = row[2 + 2*i:4 + 2*i]
        if verdict["class"] not in ("VALID", "ILLEGAL", "UNKNOWN"):
            raise Refused("missing upstream classification")
        results.append({"principal": principal, "upstream_result": verdict["class"],
                        "authorization_label": authorization["text"]})
    if any(r["upstream_result"] != "VALID" for r in results):
        raise Refused(f"upstream rejected or could not judge a cell: {results}")
    return results


def assess_all(reports, roster):
    """Account for an explicit full operation roster before accepting any result.

    Both arguments are sequences, so duplicate method/URI entries cannot vanish
    through dictionary construction. Each roster entry is (method, uri, users);
    each report entry is (method, uri, html). No expected cells are optional.
    """
    expected = {}
    for method, uri, users in roster:
        key = (method, uri)
        if key in expected:
            raise Refused("duplicate expected operation")
        expected[key] = users
    if not expected:
        raise Refused("zero expected operations")
    found = {}
    for method, uri, html in reports:
        key = (method, uri)
        if key in found or key not in expected:
            raise Refused("duplicate or unexpected operation report")
        found[key] = assess(html, method, uri, expected[key])
    if found.keys() != expected.keys():
        raise Refused("missing expected operation reports")
    return [{"method": method, "uri": uri, "cells": found[(method, uri)]}
            for method, uri in expected]
